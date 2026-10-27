using Respawn.Core;

namespace Respawn.Techniques.IFEO
{
    public static class IFEOKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-ifeo",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                RequiresAdmin = true,
                Trigger       = "On launch of target process",
                Note          = "To maintain stealth, the malicious payload must be programmed to silently launch the original executable."            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}