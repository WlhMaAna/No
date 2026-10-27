namespace Respawn.CLI
{
    public static class ArgumentParser
    {
        public static Core.ExecutionContext Parse(string[] args)
        {
            var ctx = new Core.ExecutionContext();

            if (args.Length == 0)
                return ctx;

            // handle: Respawn.exe list
            if (args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Action = "list";
                return ctx;
            }

            // handle: Respawn.exe --help / -h
            if (args[0].Equals("--help", StringComparison.OrdinalIgnoreCase) ||
                args[0].Equals("-h", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Action = "help";
                return ctx;
            }

            // parse all other flags
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--technique":
                    case "-t":
                        ctx.Technique = Next(args, i++);
                        break;
                    case "--action":
                    case "-a":
                        ctx.Action = Next(args, i++);
                        break;
                    case "--payload":
                    case "-p":
                        ctx.Payload = Next(args, i++);
                        break;
                    case "--name":
                    case "-n":
                        ctx.Name = Next(args, i++);
                        break;
                    case "--key":
                    case "-k":
                        ctx.Key = Next(args, i++);
                        break;
                    case "--folder":
                    case "-f":
                        ctx.Folder = Next(args, i++);
                        break;
                    case "--trigger":
                    case "-tr":
                        ctx.Trigger = Next(args, i++);
                        break;
                    case "--interval":
                    case "-i":
                        ctx.Interval = Next(args, i++);
                        break;
                    case "--user":
                    case "-u":
                        ctx.User = Next(args, i++);
                        break;
                    case "--hidden":
                    case "-hi":
                        ctx.Hidden = true;
                        break;
                    case "--displayname":
                    case "-dn":
                        ctx.DisplayName = Next(args, i++);
                        break;
                    case "--description":
                    case "-d":
                        ctx.Description = Next(args, i++);
                        break;
                    case "--starttype":
                    case "-st":
                        ctx.StartType = Next(args, i++);
                        break;
                    case "--consumer":
                    case "-c":
                        ctx.Consumer = Next(args, i++);
                        break;
                    case "--script":
                    case "-sc":
                        ctx.Script = Next(args, i++);
                        break;
                    case "--verbose":
                    case "-v":
                        ctx.Verbose = true;
                        break;
                    case "--help":
                    case "-h":
                        ctx.Action = "help";
                        break;
                }
            }

            return ctx;
        }

        private static string Next(string[] args, int i)
        {
            if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                return args[i + 1];

            return string.Empty;
        }
    }
}