using Respawn.Core;

namespace Respawn.Techniques.Winlogon
{
    public static class WinlogonKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "userinit",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Append exe to Userinit value, runs during logon alongside userinit.exe. Default: C:\\Windows\\system32\\userinit.exe,"
            },
            new TechniqueOption
            {
                Id            = "shell",
                Path          = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                RequiresAdmin = true,
                Trigger       = "Logon",
                Note          = "Append exe to Shell value, runs alongside explorer.exe. Default: explorer.exe"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}