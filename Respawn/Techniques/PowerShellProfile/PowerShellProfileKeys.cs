using Respawn.Core;

namespace Respawn.Techniques.PowerShellProfile
{
    public static class PowerShellProfileKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "current-user",
                Path          = @"%USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
                RequiresAdmin = false,
                Trigger       = "Every time PowerShell opens for current user",
                Note          = "No admin required. Profile script runs automatically when PowerShell starts for the current user."
            },
            new TechniqueOption
            {
                Id            = "all-users",
                Path          = @"%ProgramFiles%\PowerShell\7\profile.ps1",
                RequiresAdmin = true,
                Trigger       = "Every time PowerShell opens for any user",
                Note          = "Requires admin. Affects all users on the system. Scripts run at every PowerShell initialization."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}