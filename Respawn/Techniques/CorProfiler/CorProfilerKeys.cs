using Respawn.Core;

namespace Respawn.Techniques.CorProfiler
{
    public static class CorProfilerKeys
    {
        public static readonly List<TechniqueOption> All = new List<TechniqueOption>
        {
            new TechniqueOption
            {
                Id            = "hkcu-profiler",
                Path          = @"HKCU\Environment",
                RequiresAdmin = false,
                Trigger       = "Every time any .NET application launches for current user",
                Note          = "Sets COR_ENABLE_PROFILING and COR_PROFILER_PATH in HKCU environment."
            },
            new TechniqueOption
            {
                Id            = "hklm-profiler",
                Path          = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                RequiresAdmin = true,
                Trigger       = "Every time any .NET application launches for any user",
                Note          = "Sets COR_ENABLE_PROFILING and COR_PROFILER_PATH in system environment."
            }
        };

        public static TechniqueOption? GetById(string id) =>
            All.FirstOrDefault(k => k.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}