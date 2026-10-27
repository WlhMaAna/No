using System;
using System.Collections.Generic;
using System.Linq;
using Respawn.Core;

namespace Respawn.Techniques.RecycleBin
{
    public static class RecycleBinKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcu-recycle",
                Path          = @"HKCU\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}",
                RequiresAdmin = false,
                Trigger       = "User Interaction (Double-clicking the Recycle Bin icon)",
                Note          = "Unprivileged hijack via the 'open' verb."
            },
            new TechniqueOption
            {
                Id            = "hkcr-recycle",
                Path          = @"HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}",
                RequiresAdmin = true,
                Trigger       = "User Interaction (Double-clicking the Recycle Bin icon)",
                Note          = "Global system-wide Recycle Bin hijack. Requires Administrator privileges."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}