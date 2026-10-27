using Respawn.Core;

namespace Respawn.Techniques.ComHijack
{
    public static class ComHijackKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcu-clsid",
                Path          = @"HKCU\Software\Classes\CLSID",
                RequiresAdmin = false,
                Trigger       = "When any application instantiates the hijacked COM object",
                Note           = "Choose a CLSID frequently instantiated by common applications."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}

/// SndVol.exe