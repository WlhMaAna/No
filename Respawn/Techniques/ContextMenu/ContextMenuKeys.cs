using System;
using System.Collections.Generic;
using System.Linq;
using Respawn.Core;

namespace Respawn.Techniques.ContextMenu
{
    public static class ContextMenuKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcr-menu",
                Path          = @"HKCR\Directory\Background\shell",
                RequiresAdmin = true,
                Trigger       = "User Interaction (Right-clicking empty space on the desktop or inside a folder)",
                Note          = "Global persistence."
            },
            new TechniqueOption
            {
                Id            = "hkcu-menu",
                Path          = @"HKCU\Software\Classes\Directory\Background\shell",
                RequiresAdmin = false,
                Trigger       = "User Interaction (Right-clicking empty space on the desktop or inside a folder)",
                Note          = "Current user only."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}