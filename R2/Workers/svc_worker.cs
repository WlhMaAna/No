using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;

        private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        private const uint SERVICE_ERROR_NORMAL = 0x00000001;

        private const uint SERVICE_START_BOOT = 0x00000000;
        private const uint SERVICE_START_AUTO = 0x00000002;
        private const uint SERVICE_START_MANUAL = 0x00000003;

        private const uint SERVICE_CONTROL_STOP = 0x00000001;

        private const uint SERVICE_STOPPED = 0x00000001;
        private const uint SERVICE_STOP_PENDING = 0x00000003;

        private static string GetDefaultPayloadPath()
        {
            try
            {
                return System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            }
            catch
            {
                return @"C:\Windows\System32\cmd.exe";
            }
        }

        private static IntPtr OpenSCManager()
        {
            return OpenSCManagerNative(
                null,
                null,
                SC_MANAGER_ALL_ACCESS);
        }

        private static IntPtr OpenServiceManager(
            IntPtr hSCManager,
            string serviceName)
        {
            return OpenServiceNative(
                hSCManager,
                serviceName,
                SERVICE_ALL_ACCESS);
        }

        public static void Info(string[] args)
        {
            // Console.WriteLine("[i] Windows Service Module");
            // Console.WriteLine();
            Console.WriteLine("[i] Default Start Command Parameters:");
            Console.WriteLine("    R2 svc Start <serviceName> <payloadPath> [startType]");
            Console.WriteLine();
            // Console.WriteLine("[i] Parameters:");
            // Console.WriteLine("    serviceName  Service name");
            // Console.WriteLine("    payloadPath  Path to service executable");
            // Console.WriteLine("    startType    boot | auto | manual");
            // Console.WriteLine();
            // Console.WriteLine("[i] Default startType: auto");
        }

        public static void Start(string[] args)
        {
            if (args == null || args.Length < 2)
            {
                Console.WriteLine(
                    "[-] Usage: Start <serviceName> <payloadPath> [startType]");
                return;
            }

            string serviceName = args[0];
            string payloadPath = args[1];

            string startTypeStr = "auto";

            if (args.Length >= 3 &&
                !string.IsNullOrEmpty(args[2]))
            {
                startTypeStr = args[2].ToLowerInvariant();
            }

            uint startType;

            switch (startTypeStr)
            {
                case "boot":
                    startType = SERVICE_START_BOOT;
                    break;

                case "manual":
                    startType = SERVICE_START_MANUAL;
                    break;

                case "auto":
                default:
                    startType = SERVICE_START_AUTO;
                    break;
            }

            IntPtr hSCManager = IntPtr.Zero;
            IntPtr hService = IntPtr.Zero;

            try
            {
                hSCManager = OpenSCManager();

                if (hSCManager == IntPtr.Zero)
                {
                    Console.WriteLine(
                        "[-] OpenSCManager failed: " +
                        new Win32Exception(
                            Marshal.GetLastWin32Error()).Message);

                    return;
                }

                hService = CreateServiceNative(
                    hSCManager,
                    serviceName,
                    serviceName,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    startType,
                    SERVICE_ERROR_NORMAL,
                    payloadPath,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null);

                if (hService == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();

                    Console.WriteLine(
                        "[-] CreateService failed: " +
                        new Win32Exception(error).Message);

                    return;
                }

                Console.WriteLine(
                    "[+] Service created successfully: " +
                    serviceName);

                Console.WriteLine(
                    "[+] Binary path: " +
                    payloadPath);

                Console.WriteLine(
                    "[+] Start type: " +
                    startTypeStr);
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    "[-] Error: " +
                    ex.Message);
            }
            finally
            {
                if (hService != IntPtr.Zero)
                    CloseServiceHandle(hService);

                if (hSCManager != IntPtr.Zero)
                    CloseServiceHandle(hSCManager);
            }
        }

        public static void Stop(string[] args)
        {
            if (args == null || args.Length < 1)
            {
                Console.WriteLine(
                    "[-] Usage: Stop <serviceName>");
                return;
            }

            string serviceName = args[0];

            IntPtr hSCManager = IntPtr.Zero;
            IntPtr hService = IntPtr.Zero;

            try
            {
                hSCManager = OpenSCManager();

                if (hSCManager == IntPtr.Zero)
                {
                    Console.WriteLine(
                        "[-] OpenSCManager failed: " +
                        new Win32Exception(
                            Marshal.GetLastWin32Error()).Message);

                    return;
                }

                hService = OpenServiceManager(
                    hSCManager,
                    serviceName);

                if (hService == IntPtr.Zero)
                {
                    Console.WriteLine(
                        "[*] Service not found: " +
                        serviceName);

                    return;
                }

                SERVICE_STATUS status = new SERVICE_STATUS();

                Console.WriteLine(
                    "[*] Stopping service: " +
                    serviceName);

                bool stopped = ControlServiceNative(
                    hService,
                    SERVICE_CONTROL_STOP,
                    ref status);

                if (!stopped)
                {
                    int error = Marshal.GetLastWin32Error();

                    // If it is already stopped, continue with deletion.
                    if (status.dwCurrentState != SERVICE_STOPPED)
                    {
                        Console.WriteLine(
                            "[-] Failed to stop service: " +
                            new Win32Exception(error).Message);

                        return;
                    }
                }

                // Wait briefly for the service to reach STOPPED.
                for (int i = 0; i < 20; i++)
                {
                    if (status.dwCurrentState == SERVICE_STOPPED)
                        break;

                    System.Threading.Thread.Sleep(250);

                    SERVICE_STATUS currentStatus =
                        new SERVICE_STATUS();

                    // Re-open/query through ControlService is not required
                    // once the service reports STOPPED.
                    if (ControlServiceNative(
                        hService,
                        SERVICE_CONTROL_STOP,
                        ref currentStatus))
                    {
                        status = currentStatus;
                    }
                    else
                    {
                        // If the service has already stopped, continue.
                        int error = Marshal.GetLastWin32Error();

                        if (error != 1061)
                            status = currentStatus;
                    }

                    if (status.dwCurrentState == SERVICE_STOPPED)
                        break;
                }

                if (status.dwCurrentState == SERVICE_STOP_PENDING)
                {
                    Console.WriteLine(
                        "[*] Service is still stopping.");
                }

                bool deleted = DeleteServiceNative(hService);

                if (!deleted)
                {
                    int error = Marshal.GetLastWin32Error();

                    Console.WriteLine(
                        "[-] DeleteService failed: " +
                        new Win32Exception(error).Message);

                    return;
                }

                Console.WriteLine(
                    "[+] Service stopped and marked for deletion: " +
                    serviceName);
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    "[-] Error: " +
                    ex.Message);
            }
            finally
            {
                if (hService != IntPtr.Zero)
                    CloseServiceHandle(hService);

                if (hSCManager != IntPtr.Zero)
                    CloseServiceHandle(hSCManager);
            }
        }

        public static void Check(string[] args)
        {
            if (args == null || args.Length < 1)
            {
                Console.WriteLine(
                    "[-] Usage: Check <serviceName>");
                return;
            }

            string serviceName = args[0];

            string registryPath =
                @"SYSTEM\CurrentControlSet\Services\" +
                serviceName;

            try
            {
                using (RegistryKey key =
                    Registry.LocalMachine.OpenSubKey(
                        registryPath,
                        false))
                {
                    if (key == null)
                    {
                        Console.WriteLine(
                            "[*] Service not found: " +
                            serviceName);

                        return;
                    }

                    object imagePath =
                        key.GetValue("ImagePath");

                    object start =
                        key.GetValue("Start");

                    string startTypeStr = "auto";

                    if (start != null)
                    {
                        int startType =
                            Convert.ToInt32(start);

                        switch (startType)
                        {
                            case 0:
                                startTypeStr = "boot";
                                break;

                            case 2:
                                startTypeStr = "auto";
                                break;

                            case 3:
                                startTypeStr = "manual";
                                break;

                            default:
                                startTypeStr = "auto";
                                break;
                        }
                    }

                    Console.WriteLine(
                        "[+] Service exists: " +
                        serviceName);

                    Console.WriteLine(
                        "[*] ImagePath: " +
                        (imagePath ?? "<not set>"));

                    Console.WriteLine(
                        "[*] Start type: " +
                        startTypeStr);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    "[-] Error: " +
                    ex.Message);
            }
        }

        // ------------------------------------------------------------
        // Native Windows Service APIs
        // ------------------------------------------------------------

        [DllImport("advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr OpenSCManagerNative(
            string lpMachineName,
            string lpDatabaseName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr CreateServiceNative(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern IntPtr OpenServiceNative(
            IntPtr hSCManager,
            string lpServiceName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll",
            SetLastError = true)]
        private static extern bool DeleteServiceNative(
            IntPtr hService);

        [DllImport("advapi32.dll",
            SetLastError = true)]
        private static extern bool ControlServiceNative(
            IntPtr hService,
            uint dwControl,
            ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll",
            SetLastError = true)]
        private static extern bool CloseServiceHandle(
            IntPtr hSCObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }
    }
}