using Respawn.Core;
using System.Collections.Generic;

namespace Respawn.Techniques.CertProp
{
    public static class CertPropKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-certprop",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc\Parameters",
                RequiresAdmin = true,
                Trigger       = "When CertPropSvc is started (manual or triggered by smart card events).",
                Note          = "Hijacks the ServiceDll value to load a custom DLL into svchost.exe."
            }
        };

        public static TechniqueOption GetById(string id) =>
            All.Find(k => k.Id.Equals(id, System.StringComparison.OrdinalIgnoreCase));
    }
}