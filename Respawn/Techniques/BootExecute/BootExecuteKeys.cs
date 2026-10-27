using Respawn.Core;

namespace Respawn.Techniques.BootExecute
{
    public static class BootExecuteKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-boot",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                RequiresAdmin = true,
                Trigger       = "Early Boot (SMSS initialization)",
                Note          = "Payload MUST be a Native NT application. Standard Win32 binaries will cause a BSOD or fail to execute."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}