# Native observation works before a broken venv can be repaired or launched.
function Get-HermesSelfUpdateInstallation {
    param([string]$InstallRoot)

    $unavailable = "Self-update protection could not be checked for this installation. Use operator-managed maintenance."
    try {
        if (-not ("HermesSelfUpdate.Installation" -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace HermesSelfUpdate {
    public static class Installation {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint GetFileAttributes(string path);
        public static string PhysicalRoot(string path) {
            using (var handle = CreateFile(System.IO.Path.GetFullPath(path), 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                var buffer = new StringBuilder(32768);
                var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0 || length >= buffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error());
                var root = buffer.ToString();
                var attributes = GetFileAttributes(root);
                if (attributes == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
                if ((attributes & 0x10) == 0) throw new InvalidOperationException("Not a directory");
                if (root.StartsWith(@"\\?\UNC\")) return @"\\" + root.Substring(8);
                return root.StartsWith(@"\\?\") ? root.Substring(4) : root;
            }
        }
        public static bool MarkerPresent(string root) {
            var attributes = GetFileAttributes(System.IO.Path.Combine(root, ".hermes-self-update-disabled"));
            if (attributes != uint.MaxValue) return true;
            var error = Marshal.GetLastWin32Error();
            // ERROR_PATH_NOT_FOUND is root uncertainty, not marker absence.
            if (error == 2) return false;
            throw new Win32Exception(error);
        }
    }
}
'@ -ErrorAction Stop
        }
        $physicalRoot = [HermesSelfUpdate.Installation]::PhysicalRoot($InstallRoot)
        if ([HermesSelfUpdate.Installation]::MarkerPresent($physicalRoot)) {
            return @{ Root = $physicalRoot; Refusal = "Self-update is disabled for this installation. Use operator-managed maintenance." }
        }
        return @{ Root = $physicalRoot; Refusal = $null }
    } catch {
        return @{ Root = $InstallRoot; Refusal = $unavailable }
    }
}
