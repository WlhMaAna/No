namespace Respawn.Core
{
    public interface ITechniqueModule
    {
        // Identity
        string Id { get; }
        string Name { get; }
        string Mitre { get; }
        string Description { get; }

        // Per-technique help text
        void ShowHelp();

        // Per-technique list-* (list-keys, list-triggers, list-types, list-folders...)
        List<TechniqueOption> ListOptions(string optionType);

        // Standard actions
        TechniqueResult Install(ExecutionContext ctx);
        TechniqueResult Remove(ExecutionContext ctx);
        TechniqueResult Verify(ExecutionContext ctx);
    }
}