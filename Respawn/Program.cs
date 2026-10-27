using Respawn.Core;
using Respawn.CLI;

namespace Respawn
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // always show banner
            // HelpRenderer.RenderBanner();

            // parse args into context
            var ctx = ArgumentParser.Parse(args);

            // no args → show general help
            if (args.Length == 0)
            {
                HelpRenderer.RenderGeneralHelp();
                return;
            }

            // global: --help / -h
            if (ctx.Action.Equals("help", StringComparison.OrdinalIgnoreCase) 
                && string.IsNullOrEmpty(ctx.Technique))
            {
                HelpRenderer.RenderGeneralHelp();
                return;
            }

            // global: list
            if (ctx.Action.Equals("list", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrEmpty(ctx.Technique))
            {
                var loader = new ModuleLoader();
                HelpRenderer.RenderTechniqueList(loader.GetAll());
                return;
            }

            // from here a technique is required
            if (string.IsNullOrEmpty(ctx.Technique))
            {
                HelpRenderer.RenderError("No technique specified. Use --technique <id> or see 'Respawn.exe list'.");
                return;
            }

            // load module loader and resolve technique
            var modules = new ModuleLoader();

            if (!modules.Exists(ctx.Technique))
            {
                HelpRenderer.RenderError($"Unknown technique '{ctx.Technique}'. Use 'Respawn.exe list' to see available techniques.");
                return;
            }

            var module = modules.GetById(ctx.Technique)!;

            // no action → show technique help
            if (string.IsNullOrEmpty(ctx.Action))
            {
                HelpRenderer.RenderTechniqueHelp(module);
                return;
            }

            // per-technique: --help
            if (ctx.Action.Equals("help", StringComparison.OrdinalIgnoreCase))
            {
                HelpRenderer.RenderTechniqueHelp(module);
                return;
            }

            // per-technique: list-* actions
            if (ctx.Action.StartsWith("list-", StringComparison.OrdinalIgnoreCase))
            {
                var optionType = ctx.Action.Substring(5); // strip "list-"
                var options = module.ListOptions(optionType);

                if (options == null || options.Count == 0)
                {
                    HelpRenderer.RenderError($"No options found for '{ctx.Action}' on technique '{ctx.Technique}'.");
                    return;
                }

                HelpRenderer.RenderOptionCards(options);
                return;
            }

            // per-technique: install / remove / verify
            TechniqueResult result = ctx.Action.ToLower() switch
            {
                "install" => module.Install(ctx),
                "remove"  => module.Remove(ctx),
                "verify"  => module.Verify(ctx),
                _ => TechniqueResult.Fail($"Unknown action '{ctx.Action}'. Use --technique {ctx.Technique} --help to see available actions.")
            };

            HelpRenderer.RenderResult(result);
        }
    }
}