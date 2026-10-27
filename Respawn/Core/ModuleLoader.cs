using System.Reflection;

namespace Respawn.Core
{
    public class ModuleLoader
    {
        private readonly List<ITechniqueModule> _modules;

        public ModuleLoader()
        {
            /// This code uses reflection to find all classes implementing ITechniqueModule, 
            /// creates their instances, sorts them by Id, 
            /// and stores them in the _modules list.
            _modules = Assembly.GetExecutingAssembly()
                .GetTypes()
                .Where(t => typeof(ITechniqueModule).IsAssignableFrom(t)
                         && !t.IsInterface
                         && !t.IsAbstract)
                .Select(t => (ITechniqueModule)Activator.CreateInstance(t)!)
                .OrderBy(m => m.Id)
                .ToList();
        }

        public List<ITechniqueModule> GetAll() => _modules;

        public ITechniqueModule? GetById(string id) =>
            _modules.FirstOrDefault(m => m.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

        public bool Exists(string id) =>
            _modules.Any(m => m.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}