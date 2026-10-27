using Respawn.Core;

namespace Respawn.Techniques.Bits
{
    public static class BitsKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "notification",
                Path          = "BITS Service",
                RequiresAdmin = false,
                Trigger       = "On job completion or error",
                Note          = "BITS job stays suspended; notification command fires on state change."            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}


/// bitsadmin /setminretrydelay SystemUpdate 0
/// bitsadmin /setnoprogresstimeout SystemUpdate 1
/// bitsadmin.exe /list /allusers
/// bitsadmin /resume SystemUpdate