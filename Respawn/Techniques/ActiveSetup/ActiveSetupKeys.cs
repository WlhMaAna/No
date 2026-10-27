using Respawn.Core;

namespace Respawn.Techniques.ActiveSetup
{
    public static class ActiveSetupKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-active", 
                Path          = @"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
                RequiresAdmin = true,
                Trigger       = "Logon (once per user)",
                Note          = "For repeated execution, the payload must delete its HKCU entry or reduce its version number after running."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}