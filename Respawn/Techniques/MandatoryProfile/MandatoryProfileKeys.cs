using System;
using System.Collections.Generic;
using System.Linq;
using Respawn.Core;

namespace Respawn.Techniques.MandatoryProfile
{
    public static class MandatoryProfileKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "man",
                Path          = @"%USERPROFILE%\NTUSER.MAN",
                RequiresAdmin = true, // UPGRADED: Requires Admin for SeBackupPrivilege
                Trigger       = "Logon",
                Note          = "Because the profile becomes mandatory, the user's environment changes will be lost on logoff."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}