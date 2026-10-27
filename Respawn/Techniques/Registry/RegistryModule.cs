using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.Registry
{
    public class RegistryModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "run";
        public string Name        => "Registry Run Keys";
        public string Mitre       => "T1547.001";
        public string Description => "Persist by abusing standard Windows Run, RunOnce, and Explorer Policy registry keys to automatically execute a payload in the background during the logon sequence.";

        // ─── Help ────────────────────────────────────────────────────────────────

    public void ShowHelp()
    {
        TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

        // 2. USAGE NOTES
        // Console.ForegroundColor = ConsoleColor.Cyan;
        // Console.WriteLine("  USAGE NOTES:");
        // Console.ResetColor();
        // Console.WriteLine("    - 'hkcu-*' keys do not require Administrator privileges");
        // Console.WriteLine("    - 'hklm-*' keys require Administrator privileges");
        // Console.WriteLine("    - RunOnce keys delete the entry after the first execution");
        // Console.WriteLine();

        // 3. OPTIONS
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  OPTIONS:");
        Console.ResetColor();
        
        TechniqueHelpBuilder.RenderOption("-k,  --key", "Target Key ID (e.g. 'hkcu-run', 'hklm-run32')");
        TechniqueHelpBuilder.RenderOption("-n,  --name", "Registry Value Name (e.g. 'OneDriveUpdate')");
        TechniqueHelpBuilder.RenderOption("-p,  --payload", "Command to execute (exe, script, or built-in tool)");
        Console.WriteLine();

        // 4. EXAMPLES
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  EXAMPLES:");
        Console.ResetColor();

        TechniqueHelpBuilder.RenderExample("Respawn -t run -a list-keys");
        TechniqueHelpBuilder.RenderExample("Respawn -t run -a install -k hkcu-run -n \"Updater\" -p \"C:\\p.exe\"");
        TechniqueHelpBuilder.RenderExample("Respawn -t run -a verify  -k hkcu-run -n \"Updater\"");
        TechniqueHelpBuilder.RenderExample("Respawn -t run -a remove  -k hkcu-run -n \"Updater\"");
    }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return RegistryKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = RegistryKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var regKey = OpenForWrite(ctx.Key, create: true);
                if (regKey == null)
                    return TechniqueResult.Denied($"Access denied opening registry key: {key.Path}");

                var existing = regKey.GetValue(ctx.Name);
                if (existing != null)
                    return TechniqueResult.Exists($"Value '{ctx.Name}' already exists under {key.Path}");

                regKey.SetValue(ctx.Name, ctx.Payload);
                return TechniqueResult.Ok($"Installed '{ctx.Name}' -> '{ctx.Payload}' under {key.Path}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Key '{ctx.Key}' requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            var key = RegistryKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var regKey = OpenForWrite(ctx.Key, create: false);
                if (regKey == null)
                    return TechniqueResult.NotFound($"Registry key not found: {key.Path}");

                var existing = regKey.GetValue(ctx.Name);
                if (existing == null)
                    return TechniqueResult.NotFound($"Value '{ctx.Name}' not found under {key.Path}");

                regKey.DeleteValue(ctx.Name);
                return TechniqueResult.Ok($"Removed '{ctx.Name}' from {key.Path}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Key '{ctx.Key}' requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: false, out string error))
                return TechniqueResult.Fail(error);

            var key = RegistryKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var regKey = OpenForRead(ctx.Key);
                if (regKey == null)
                    return TechniqueResult.NotFound($"Registry key not found: {key.Path}");

                var value = regKey.GetValue(ctx.Name)?.ToString();
                if (value == null)
                    return TechniqueResult.NotFound($"Value '{ctx.Name}' not found under {key.Path}");

                return TechniqueResult.Ok($"Verified '{ctx.Name}' -> '{value}' under {key.Path}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Key '{ctx.Key}' requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Key))
            {
                error = "No key specified. Use -k <key-id> or see -a list-keys.";
                return false;
            }
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No name specified. Use -n <name>.";
                return false;
            }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <payload>.";
                return false;
            }
            error = string.Empty;
            return true;
        }

        private RegistryKey? OpenForWrite(string keyId, bool create)
        {
            var (hive, path) = ResolvePath(keyId);
            return create
                ? hive.CreateSubKey(path, writable: true)
                : hive.OpenSubKey(path, writable: true);
        }

        private RegistryKey? OpenForRead(string keyId)
        {
            var (hive, path) = ResolvePath(keyId);
            return hive.OpenSubKey(path, writable: false);
        }

        private (RegistryKey hive, string path) ResolvePath(string keyId)
        {
            return keyId.ToLower() switch
            {
                "hkcu-run"          => (Microsoft.Win32.Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run"),
                "hkcu-runonce"      => (Microsoft.Win32.Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                "hkcu-policies-run" => (Microsoft.Win32.Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                "hkcu-run-services" => (Microsoft.Win32.Registry.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunServices"),
                "hklm-run"          => (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                "hklm-runonce"      => (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                "hklm-run32"        => (Microsoft.Win32.Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                "hklm-policies-run" => (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                "hklm-run-services" => (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunServices"),
                _                   => throw new ArgumentException($"Unknown key id: {keyId}")
            };
        }
    }
}