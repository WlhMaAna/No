namespace Respawn.Core
{
    public class TechniqueOption
    {
        public string Id { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public bool RequiresAdmin { get; set; }
        public string Trigger { get; set; } = string.Empty;
        public string Note { get; set; } = string.Empty;
    }
}