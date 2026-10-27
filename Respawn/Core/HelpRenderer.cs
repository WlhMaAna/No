namespace Respawn.Core
{
    public static class HelpRenderer
    {
        // ─── Banner ──────────────────────────────────────────────────────────────

        public static void RenderBanner()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"  ██████╗ ███████╗███████╗██████╗  █████╗ ██╗    ██╗███╗   ██╗");
            Console.WriteLine(@"  ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██║     ██║████╗  ██║");
            Console.WriteLine(@"  ██████╔╝█████╗  ███████╗██████╔╝███████║██║ █╗ ██║██╔██╗ ██║");
            Console.WriteLine(@"  ██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██╔══██║██║███╗██║██║╚██╗██║");
            Console.WriteLine(@"  ██║  ██║███████╗███████║██║     ██║  ██║╚███╔███╔╝██║ ╚████║");
            Console.WriteLine(@"  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝");
            
            // Status Bar - High Utility Context
            bool isAdmin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  > Persistence Simulation Framework       Authorized Use Only");
            Console.Write("  > CONTEXT: ");
            Console.ForegroundColor = isAdmin ? ConsoleColor.Red : ConsoleColor.Yellow;
            Console.Write(isAdmin ? "ADMINISTRATOR" : "USER");
            
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("                               VERSION: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("1.0.0");
            
            Console.ResetColor();
            Console.WriteLine($"  {new string('─', 62)}");
        }

        // ─── General Help ────────────────────────────────────────────────────────

        public static void RenderGeneralHelp()
        {
            RenderBanner();

            // 1. FLEXIBLE SYNTAX
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  GENERAL SYNTAX");
            Console.ResetColor();
            Console.WriteLine("    Respawn -t <id> -a <action> [options]\n");

            // 2. CORE ARGUMENTS (Aligned for fast scanning)
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    -t, --technique   "); Console.ResetColor(); Console.WriteLine("Technique ID (e.g., registry, wmi, etc.)");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    -a, --action      "); Console.ResetColor(); Console.WriteLine("install | remove | verify | list-*");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    -n, --name        "); Console.ResetColor(); Console.WriteLine("Identifier (Task name, Service name, etc.)");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    -p, --payload     "); Console.ResetColor(); Console.WriteLine("Target path (EXE, DLL, BAT, PS1, etc.)\n");

            // 3. DISCOVERY
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  DISCOVERY");
            Console.ResetColor();
            Console.WriteLine("    Respawn list               List all available techniques");
            Console.WriteLine("    Respawn -t <id> --help     Show technique-specific help\n");

            // 4. EXAMPLE
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  EXAMPLE");
            Console.ResetColor();
            Console.WriteLine("    Respawn -t bits -a install -n \"SystemUpdate\" -p \"C:\\p.exe\"");
            
            Console.ResetColor();
            Console.WriteLine($"  {new string('─', 62)}");
            Console.WriteLine();
        }

        // ─── Technique List ──────────────────────────────────────────────────────

        public static void RenderTechniqueList(List<ITechniqueModule> modules)  
        {
            RenderBanner();

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  AVAILABLE TECHNIQUES");
            Console.ResetColor();
            Console.WriteLine();

            // High-contrast headers
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {"ID",-20} {"NAME",-30} {"MITRE",-12}");
            Console.WriteLine($"  {new string('─', 62)}");

            foreach (var m in modules)
            {
                // Highlight the ID as the primary key for commands
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  {m.Id,-20}");

                // Formal name in a neutral color
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.Write($"{m.Name,-30}");

                // MITRE ID in DarkGray
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"{m.Mitre,-12}");
            }

            Console.ResetColor();
            Console.WriteLine($"  {new string('─', 62)}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Use 'Respawn -t <id> --help' for technique descriptions.\n");
            Console.ResetColor();
        }

        // ─── Per-Technique Help ──────────────────────────────────────────────────

        public static void RenderTechniqueHelp(ITechniqueModule module)
        {
            Console.Clear();
            RenderBanner();

            // 1. TECHNIQUE HEADER (Auto-generated)
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("  TECHNIQUE: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{module.Name} ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"({module.Mitre})");
            
            // 2. DESCRIPTION
            Console.ResetColor();
            for (int i = 0; i < module.Description.Length; i += 62)
            {
                Console.WriteLine("    " + module.Description.Substring(i, Math.Min(62, module.Description.Length - i)));
            }
            Console.WriteLine();

            // 3. MODULE-SPECIFIC CONTENT
            // This calls the specific module's unique logic (Actions, Options, etc.)
            module.ShowHelp();

            // 4. FOOTER
            Console.ResetColor();
            Console.WriteLine($"  {new string('─', 62)}");
            Console.WriteLine();
        }
        // ─── Option Cards (list-keys, list-triggers, list-types...) ─────────────

        public static void RenderOptionCards(List<TechniqueOption> options)
        {
            Console.WriteLine();
            foreach (var opt in options)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"  [{opt.Id}]");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(opt.Path))
                    Console.WriteLine($"    Path      : {opt.Path}");

                Console.WriteLine($"    Admin     : {(opt.RequiresAdmin ? "Yes" : "No")}");
                Console.WriteLine($"    Trigger   : {opt.Trigger}");
                Console.WriteLine($"    Note      : {opt.Note}");
                Console.WriteLine();
            }
        }

        // ─── Result Output ───────────────────────────────────────────────────────

        public static void RenderResult(TechniqueResult result)
        {
            Console.WriteLine();
            switch (result.Status)
            {
                case ResultStatus.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  [+] {result.Message}");
                    break;
                case ResultStatus.AlreadyExists:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"  [!] {result.Message}");
                    break;
                case ResultStatus.NotFound:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"  [!] {result.Message}");
                    break;
                case ResultStatus.AccessDenied:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  [x] {result.Message}");
                    break;
                case ResultStatus.Failure:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  [-] {result.Message}");
                    break;
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        // ─── Error Output ────────────────────────────────────────────────────────

        public static void RenderError(string message)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [!] Error: {message}");
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}