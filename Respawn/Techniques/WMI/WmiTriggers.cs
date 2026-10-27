using Respawn.Core;

namespace Respawn.Techniques.WMI
{
    public static class WmiTriggers
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "logon",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Fires when a user logon session is created"
            },
            new TechniqueOption
            {
                Id            = "boot",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Boot",
                Note          = "Fires on system boot via shutdown event monitoring"
            },
            new TechniqueOption
            {
                Id            = "timer",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Repeating",
                Note          = "Fires every X seconds, requires -i value"
            },
            new TechniqueOption
            {
                Id            = "process",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Process start",
                Note          = "Fires on every new process creation on the system"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

        // WMI query strings for each trigger
        public static string GetQuery(string triggerId, string interval = "") =>
            triggerId.ToLower() switch
            {
                "logon"   => "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'",
                "boot"    => "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_ComputerSystem'",
                "timer"   => $"SELECT * FROM __TimerEvent WHERE TimerID = 'RespawnTimer' AND NumFiringCount > 0",
                "process" => "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'",
                _         => string.Empty
            };
    }
}