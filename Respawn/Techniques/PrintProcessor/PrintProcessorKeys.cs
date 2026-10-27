using Respawn.Core;

namespace Respawn.Techniques.PrintProcessor
{
    public static class PrintProcessorKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hklm-print",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors",
                RequiresAdmin = true,
                Trigger       = "Boot — loaded by spoolsv.exe at startup",
                Note           = "DLL must export OpenPrintProcessor. Loaded into spoolsv.exe at boot."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}


/// Print processors are DLLs loaded by the spooler service (spoolsv.exe) whenever a print job uses that processor.