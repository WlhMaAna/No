using Respawn.Core;

namespace Respawn.Techniques.PathInterception
{
    public static class PathInterceptionKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "system-path",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment [PATH]",
                RequiresAdmin = true,
                Trigger       = "When target executable is launched without full path",
                Note          = "Affects all users. Target must be launched without a full path to be intercepted."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}