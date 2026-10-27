using Respawn.Core;

namespace Respawn.Techniques.BootVerify
{
    public static class BootVerifyKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-bootverify",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\BootVerificationProgram",
                RequiresAdmin = true,
                Trigger       = "First User Logon (Post-Boot)",
                Note          = "Runs as SYSTEM. Stable and rarely monitored by standard EDRs."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}