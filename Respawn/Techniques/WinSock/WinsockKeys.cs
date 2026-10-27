using Respawn.Core;
using System.Collections.Generic;

namespace Respawn.Techniques.Winsock
{
    public static class WinsockKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-winsock",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\000000000005",
                RequiresAdmin = true,
                Trigger       = "Network Location Awareness (NLA) checks and network resolution.",
                Note          = "Hijacks the NLAapi.dll provider. Triggers whenever processes check network status."
            }
        };

        public static TechniqueOption GetById(string id) =>
            All.Find(k => k.Id.Equals(id, System.StringComparison.OrdinalIgnoreCase));
    }
}