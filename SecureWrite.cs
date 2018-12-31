using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Mono.Unix.Native;
using OpenRA;

namespace tlstest
{
    public static class SecureWrite
    {
        public static void Write(string file, SecureWriteCallback callback)
        {
            if (Platform.CurrentPlatform == PlatformType.Windows)
            {
                WriteWindows(file, callback);
            }
            else
            {
                WriteUnix(file, callback);
            }
        }

        public delegate void SecureWriteCallback(FileStream stream);

        public static void WriteWindows(string file, SecureWriteCallback callback)
        {
            using (FileStream stream = File.Open(file, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                FileSecurity acl = File.GetAccessControl(file);

                acl.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule entry in acl.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    acl.PurgeAccessRules(entry.IdentityReference);
                }

                acl.AddAccessRule(new FileSystemAccessRule(stream.GetAccessControl().GetOwner(typeof(NTAccount)), FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(file, acl);
                callback.Invoke(stream);
            }
        }

        public static void WriteUnix(string file, SecureWriteCallback callback)
        {
            FilePermissions oldUmask = Syscall.umask(FilePermissions.S_IXUSR | FilePermissions.S_IRGRP | FilePermissions.S_IWGRP | FilePermissions.S_IXGRP | FilePermissions.S_IROTH | FilePermissions.S_IWOTH | FilePermissions.S_IXOTH);
            using (FileStream stream = File.Open(file, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                callback.Invoke(stream);
            }
            Syscall.umask(oldUmask);
        }
    }
}
