using Respawn.Core;

namespace Respawn.Techniques.Service
{
    public static class ServiceTypes
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "auto",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Boot",
                Note          = "Starts automatically at every system boot"
            },
            new TechniqueOption
            {
                Id            = "boot",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "Boot (early)",
                Note          = "Starts during kernel initialization before most services"
            },
            new TechniqueOption
            {
                Id            = "manual",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "On demand",
                Note          = "Only starts when explicitly triggered, less suspicious"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}