using Respawn.Core;

namespace Respawn.Techniques.Registry
{
    public static class RegistryKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcu-run",
                Path          = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                RequiresAdmin = false,
                Trigger       = "Logon",
                Note          = "Runs at every user logon"
            },
            new TechniqueOption
            {
                Id            = "hkcu-runonce",
                Path          = @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                RequiresAdmin = false,
                Trigger       = "Logon (once)",
                Note          = "Runs once at next logon then deletes itself"
            },
            new TechniqueOption
            {
                Id            = "hklm-run",
                Path          = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Runs at logon for all users"
            },
            new TechniqueOption
            {
                Id            = "hklm-runonce",
                Path          = @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                RequiresAdmin = true,
                Trigger       = "Logon (once)",
                Note          = "Runs once at next logon for all users"
            },
            new TechniqueOption
            {
                Id            = "hklm-run32",
                Path          = @"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Runs at logon, targets 32-bit apps on 64-bit OS"
            },
            new TechniqueOption
            {
                Id            = "hkcu-policies-run",
                Path          = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                RequiresAdmin = false,
                Trigger       = "Logon",
                Note          = "Runs at logon via group policy, less monitored"
            },
            new TechniqueOption
            {
                Id            = "hklm-policies-run",
                Path          = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Runs at logon for all users via group policy"
            },
            new TechniqueOption
            {
                Id            = "hkcu-run-services",
                Path          = @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices",
                RequiresAdmin = false,
                Trigger       = "Logon",
                Note          = "Legacy key, still works on some Windows versions"
            },
            new TechniqueOption
            {
                Id            = "hklm-run-services",
                Path          = @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Legacy key, system-wide, still works on some versions"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}