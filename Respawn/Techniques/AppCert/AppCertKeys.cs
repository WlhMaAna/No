using Respawn.Core;

namespace Respawn.Techniques.AppCert
{
    public static class AppCertKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-appcert",
                Path          = @"HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls",
                RequiresAdmin = true,
                Trigger       = "Process Creation",
                Note          = "The DLL is loaded into every process calling CreateProcess. Ensure the DLL is stable to avoid system-wide crashes."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}