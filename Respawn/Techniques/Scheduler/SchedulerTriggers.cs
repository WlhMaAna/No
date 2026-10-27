using Respawn.Core;

namespace Respawn.Techniques.Scheduler
{
    public static class SchedulerTriggers
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "logon",
                Path          = string.Empty,
                RequiresAdmin = false,
                Trigger       = "Logon",
                Note          = "Fires at user logon. Current user by default, use -u SYSTEM for all users (requires admin)"            },
            new TechniqueOption
            {
                Id            = "boot",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Boot",
                Note          = "Fires at system boot before user logs on, requires admin"
            },
            new TechniqueOption
            {
                Id            = "interval",
                Path          = string.Empty,
                RequiresAdmin = false,
                Trigger       = "Repeating",
                Note          = "Fires repeatedly on a set interval, requires -i value"
            },
            new TechniqueOption
            {
                Id            = "idle",
                Path          = string.Empty,
                RequiresAdmin = false,
                Trigger       = "Idle",
                Note          = "Fires when system has been idle for 10 minutes"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}