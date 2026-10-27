using Respawn.Core;

namespace Respawn.Techniques.LSA
{
    public static class LSAKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-lsa",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                RequiresAdmin = true,
                Trigger       = "Boot — loaded into lsass.exe at startup",
                Note          = "A bug or crash in your payload DLL will cause a fatal system crash and prevent Windows from booting entirely."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}