using Respawn.Core;

namespace Respawn.Techniques.SilentExit
{
    public static class SilentExitKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-silent",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                RequiresAdmin = true,
                Trigger       = "On termination of the target process",
                Note          = "Requires GlobalFlag 0x200 to be set in the corresponding IFEO key."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}