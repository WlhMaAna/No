using Respawn.Core;

namespace Respawn.Techniques.ShortcutModification
{
    public static class ShortcutFolders
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "desktop",
                Path          = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                RequiresAdmin = false,
                Trigger       = "On shortcut click",
                Note          = "Current user desktop shortcuts"
            },
            new TechniqueOption
            {
                Id            = "common-desktop",
                Path          = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                RequiresAdmin = true,
                Trigger       = "On shortcut click",
                Note          = "All users desktop shortcuts"
            },
            new TechniqueOption
            {
                Id            = "startmenu",
                Path          = Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                RequiresAdmin = false,
                Trigger       = "On shortcut click",
                Note          = "Current user start menu shortcuts"
            },
            new TechniqueOption
            {
                Id            = "common-startmenu",
                Path          = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                RequiresAdmin = true,
                Trigger       = "On shortcut click",
                Note          = "All users start menu shortcuts"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}