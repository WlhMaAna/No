namespace Respawn.Core
{
    public class ExecutionContext
    {
        // Global options (every technique uses these)
        public string Technique   { get; set; } = string.Empty;
        public string Action      { get; set; } = string.Empty;
        public string Payload     { get; set; } = string.Empty;
        public string Name        { get; set; } = string.Empty;
        public bool   Verbose     { get; set; } = false;

        // Registry specific
        public string Key         { get; set; } = string.Empty;

        // Scheduler specific
        public string Trigger     { get; set; } = string.Empty;
        public string Interval    { get; set; } = string.Empty;
        public string User        { get; set; } = string.Empty;
        public bool   Hidden      { get; set; } = false;

        // Service specific
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string StartType   { get; set; } = string.Empty;

        // Startup specific
        public string Folder      { get; set; } = string.Empty;

        // WMI specific
        public string Consumer    { get; set; } = string.Empty;
        public string Script      { get; set; } = string.Empty;
    }
}