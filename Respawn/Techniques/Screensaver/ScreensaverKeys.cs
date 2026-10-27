using Respawn.Core;

namespace Respawn.Techniques.Screensaver
{
    public static class ScreensaverKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcu-screensaver",
                Path          = @"HKCU\Control Panel\Desktop",
                RequiresAdmin = false,
                Trigger       = "After inactivity timeout",
                Note           = "Replaces screensaver via SCRNSAVE.EXE. No admin needed."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}