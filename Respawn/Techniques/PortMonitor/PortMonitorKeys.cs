using Respawn.Core;

namespace Respawn.Techniques.PortMonitor
{
    public static class PortMonitorKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-port",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors",
                RequiresAdmin = true,
                Trigger       = "Boot — loaded by spoolsv.exe at startup",
                Note          = "DLL must export InitializePrintMonitor2 or InitializePrintMonitor."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(k.Id, StringComparison.OrdinalIgnoreCase));
    }
}


/// Port monitors are DLLs loaded by the spooler service to manage printer ports.