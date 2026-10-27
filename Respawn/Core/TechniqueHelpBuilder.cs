using System;
using System.Text;

namespace Respawn.Core
{
    public static class TechniqueHelpBuilder
    {
        private const int ColumnWidth = 25;

        public static void RenderHeader(string title, string mitreId, string description)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n  TECHNIQUE: {title} ({mitreId})");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {description}");
            Console.ResetColor();
            Console.WriteLine();
        }

        public static void RenderSection(string label, string[] items)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  {label.ToUpper()}:");
            Console.ResetColor();
            foreach (var item in items)
            {
                Console.WriteLine($"    {item}");
            }
            Console.WriteLine();
        }

        public static void RenderOption(string flag, string description, bool required = false)
        {
            string reqTag = required ? "[REQUIRED] " : "";
            Console.Write($"    {flag,-ColumnWidth}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"{reqTag}{description}");
            Console.ResetColor();
        }

        public static void RenderExample(string command)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("    > ");
            Console.ResetColor();
            Console.WriteLine(command);
        }

        public static void RenderShowHelp(string priv, string list)
        {
            if (priv == "p1") {
                // 0. MINIMUM PRIVILEGE
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  MINIMUM PRIVILEGE:");
                Console.ResetColor();
                Console.WriteLine("    Local Administrator (UAC elevated)");
                Console.WriteLine("    Reason: Requires write access to HKLM registry hive.\n");
            }

            if (priv == "p3") {
                // 0. MINIMUM PRIVILEGE
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  MINIMUM PRIVILEGE:");
                Console.ResetColor();
                Console.WriteLine("    Local Administrator (UAC elevated)");
                Console.WriteLine("    Reason: Requires SeBackupPrivilege to snapshot the live hive\n");
            }
            if (priv == "p4") {
                // 0. MINIMUM PRIVILEGE
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  MINIMUM PRIVILEGE:");
                Console.ResetColor();
                Console.WriteLine("    Local Administrator (UAC elevated)");
                Console.WriteLine("    Reason: Interact with the SCM API and write to the system-wide HKLM\n");
            }
            if (priv == "p5") {
                // 0. MINIMUM PRIVILEGE
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  MINIMUM PRIVILEGE:");
                Console.ResetColor();
                Console.WriteLine("    Local Administrator (UAC elevated)");
                Console.WriteLine("    Reason: Create classes and instances within the `root\\subscription` WMI namespace\n");
            }

            // 1. ACTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ACTIONS:");
            Console.ResetColor();
            if (list == "keys") {
                Console.WriteLine("    install, verify, remove, list-keys\n");
            }
            if (list == "folders") {
                Console.WriteLine("    install, verify, remove, list-folders\n");
            }
            if (list == "triggers") {
                Console.WriteLine("    install, verify, remove, list-triggers\n");
            }
            if (list == "types") {
                Console.WriteLine("    install, verify, remove, list-types\n");
            }
            if (list == "wmi") {
            Console.WriteLine("    install, remove, verify, list-triggers, list-consumers\n");
            }
        }
    }
}