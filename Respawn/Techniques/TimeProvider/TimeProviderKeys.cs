using Respawn.Core;

namespace Respawn.Techniques.TimeProvider
{
    public static class TimeProviderKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-time",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders",
                RequiresAdmin = true,
                Trigger       = "Boot — loaded by svchost.exe running W32Time service",
                Note          = "DLL loads into svchost.exe (W32Time) at boot as SYSTEM. DLL must export the TimeProvOpen function to be valid."
           }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}


/// Restart-Service W32Time