using Respawn.Core;

namespace Respawn.Techniques.AppInit
{
    public static class AppInitKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-appinit",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                RequiresAdmin = true,
                Trigger       = "Process launch (any process loading user32.dll)",
                Note          = "DLLs must be signed if Secure Boot is enabled on the target."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}