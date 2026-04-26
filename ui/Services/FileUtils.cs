using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CloudRedirect.Services
{
    internal static class FileUtils
    {
        // Why these helpers don't use File.WriteAllBytes / WriteAllText /
        // WriteAllLines / File.Copy directly:
        //
        // The convenience APIs return after closing their FileStream, which
        // only flushes user-mode buffers down to the OS. The bytes then sit
        // in the page cache. NTFS journals the rename's metadata change
        // aggressively, so a power loss between File.Move and the OS
        // lazy-flushing the data leaves the published target pointing at an
        // inode whose data blocks were never written -- the file opens as
        // zeros or torn content even though the rename itself survived.
        //
        // FileStream.Flush(flushToDisk: true) routes through FlushFileBuffers
        // on Windows, forcing the data blocks to physical storage before the
        // handle closes. We then File.Move the .tmp over the target.
        //
        // Same defense also applied to AtomicCopy: File.Copy is replaced by
        // a manual read/write so we own the destination handle and can flush
        // it before close.

        private static void WriteFlushAndPublish(string path, System.Action<FileStream> writer)
        {
            var tmp = path + ".tmp";
            try
            {
                using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write,
                                               FileShare.None, 81920, FileOptions.None))
                {
                    writer(fs);
                    // The load-bearing call: forces the file's data blocks
                    // out of the OS page cache and onto stable storage
                    // before we publish the rename.
                    fs.Flush(flushToDisk: true);
                }
                File.Move(tmp, path, overwrite: true);
            }
            catch
            {
                try { File.Delete(tmp); } catch { }
                throw;
            }
        }

        public static void AtomicWriteAllBytes(string path, byte[] data)
        {
            WriteFlushAndPublish(path, fs => fs.Write(data, 0, data.Length));
        }

        public static void AtomicWriteAllText(string path, string content)
        {
            // Match File.WriteAllText's default: UTF-8 without BOM.
            var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content);
            WriteFlushAndPublish(path, fs => fs.Write(bytes, 0, bytes.Length));
        }

        public static void AtomicWriteAllLines(string path, IEnumerable<string> lines)
        {
            // Match File.WriteAllLines's default: UTF-8 without BOM, Environment.NewLine.
            WriteFlushAndPublish(path, fs =>
            {
                using var sw = new StreamWriter(fs,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                    bufferSize: 1024,
                    leaveOpen: true);
                foreach (var line in lines)
                {
                    sw.WriteLine(line);
                }
                sw.Flush();
            });
        }

        // Copies sourcePath to destPath atomically: writes a sibling .tmp
        // first with FlushFileBuffers before close, then File.Move(overwrite:true)
        // which is rename-on-NTFS. A process kill or power loss mid-copy
        // leaves the .tmp orphan but never a torn destPath. Used by the
        // patcher Backup helper so an interrupted backup cannot leave a
        // fragment that a later Restore would write over a working binary
        // with.
        public static void AtomicCopy(string sourcePath, string destPath)
        {
            WriteFlushAndPublish(destPath, fs =>
            {
                using var src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                                               FileShare.Read, 81920, FileOptions.SequentialScan);
                src.CopyTo(fs);
            });
        }

        public static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F1} GB";
        }
    }
}
