using Respawn.Core;

namespace Respawn.Techniques.WerHijack
{
    public static class WerHijackKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-debugger",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs",
                RequiresAdmin = true,
                Trigger       = "When any process hangs or crashes",
                Note          = "Registers payload as a custom debugger via WER Hangs key. Fires when WerFault.exe is invoked."
            },
            new TechniqueOption
            {
                Id            = "hklm-runtimeexception",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                RequiresAdmin = true,
                Trigger       = "When any process crashes with unhandled exception",
                Note          = "Registers payload as the AeDebug debugger. Fires on every unhandled exception system-wide."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}