using Respawn.Core;

namespace Respawn.Techniques.WMI
{
    public static class WmiConsumers
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "cmdline",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "On event",
                Note          = "Executes a binary directly when the event fires"
            },
            new TechniqueOption
            {
                Id            = "script",
                Path          = string.Empty,
                RequiresAdmin = true,
                Trigger       = "On event",
                Note          = "Executes a VBScript file when the event fires, requires --script path"
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

        // WMI consumer class name for each consumer type
        public static string GetConsumerClass(string consumerId) =>
            consumerId.ToLower() switch
            {
                "cmdline" => "CommandLineEventConsumer",
                "script"  => "ActiveScriptEventConsumer",
                _         => string.Empty
            };
    }
}