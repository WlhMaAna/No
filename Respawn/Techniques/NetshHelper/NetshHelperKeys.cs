using Respawn.Core;

namespace Respawn.Techniques.NetshHelper
{
    public static class NetshHelperKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-netsh",
                Path          = @"HKLM\SOFTWARE\Microsoft\NetSh",
                RequiresAdmin = true,
                Trigger       = "When netsh.exe is executed",
                Note          = "DLL must export the InitHelperDll function to be valid."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}