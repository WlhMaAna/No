using Respawn.Core;

namespace Respawn.Techniques.Startup
{
    public static class StartupFolders
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "user",
                Path          = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                @"Microsoft\Windows\Start Menu\Programs\Startup"),
                RequiresAdmin = false,
                Trigger       = "Logon",
                Note          = "Runs at logon for the current user only"
            },
            new TechniqueOption
            {
                Id            = "system",
                Path          = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                @"Microsoft\Windows\Start Menu\Programs\Startup"),
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Runs at logon for all users on the machine"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}