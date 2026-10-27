using Respawn.Core;

namespace Respawn.Techniques.LogonScript
{
    public static class LogonScriptKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcu-logon",
                Path          = @"HKCU\Environment",
                RequiresAdmin = false,
                Trigger       = "Logon",
                Note          = "Executed by userinit.exe at every logon. A synchronous or hanging payload will indefinitely freeze the user's login screen."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}