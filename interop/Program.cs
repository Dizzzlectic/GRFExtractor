using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Reflection;
using GRF.Core;
using GRF.GrfSystem;
using Utilities.Services;

// Intentionally uses GRFEditor's own file-table parser and decompression path.
// JSON lines make it possible to compare every logical entry with another reader.
Console.OutputEncoding = new UTF8Encoding(false);
EncodingService.DisplayEncoding = Encoding.GetEncoding(949);
Compression.CompressionAlgorithm = Compression.ZlibDotNet;
Settings.CpuMonitoringEnabled = false;
Settings.TempPath = Path.Combine(Path.GetTempPath(), "grf-interop-" + System.Diagnostics.Process.GetCurrentProcess().Id);

if (args.Length == 2 && args[0] == "--vectors") {
    try {
        var decoder = typeof(GrfHolder).Assembly.GetType("GRF.Core.GrfCompression.ProtectedGrfDecoder", true)!;
        var keyMethod = decoder.GetMethod("DecodeArchiveKeys", BindingFlags.NonPublic | BindingFlags.Static)!;
        var decodeMethod = decoder.GetMethod("Decode", BindingFlags.NonPublic | BindingFlags.Static)!;
        using var reader = new BinaryReader(File.OpenRead(args[1]));
        byte[] Field() => reader.ReadBytes(reader.ReadInt32());
        int count = reader.ReadInt32(), accepted = 0, rejected = 0;
        for (int index = 0; index < count; index++) {
            string tag = Encoding.UTF8.GetString(Field());
            byte[] name = Field(), keyBlock = Field(), payload = Field(), expected = Field();
            int size = reader.ReadInt32();
            bool positive = tag.StartsWith("boundary-", StringComparison.Ordinal) ||
                new[] { "raw-name", "zlib-rc6-footer", "lz4-aes-checksum", "threeway-partial", "body1-lz4" }.Contains(tag);
            try {
                object keys = keyMethod.Invoke(null, new object[] { keyBlock })!;
                byte[] actual = payload.Length == 0 ? Array.Empty<byte>() :
                    (byte[])decodeMethod.Invoke(null, new object[] { payload, name, size, keys })!;
                if (!positive || !actual.SequenceEqual(expected))
                    throw new Exception("Unexpected accepted output: " + tag);
                accepted++;
            }
            catch (TargetInvocationException error) when (!positive && error.InnerException is InvalidDataException) {
                rejected++;
            }
        }
        if (count != 40 || accepted != 25 || rejected != 15 || reader.BaseStream.Position != reader.BaseStream.Length)
            throw new Exception("Unexpected vector totals");
        Console.Error.WriteLine($"PASS GRFEditor vectors: {accepted} accepted, {rejected} rejected");
        return 0;
    }
    catch (Exception error) {
        Console.Error.WriteLine(error);
        return 1;
    }
}

if (args.Length is < 1 or > 2) {
    Console.Error.WriteLine("Usage: GrfInterop ARCHIVE [EXPECTED_CONTENT_DIRECTORY] | --vectors FIXTURE_BUNDLE");
    return 2;
}

try {
    using var grf = new GrfHolder(Path.GetFullPath(args[0]));
    if (grf.Header.FoundErrors)
        throw new InvalidDataException(string.Join("; ", grf.Header.Errors));
    int checkedCount = 0;
    foreach (var entry in grf.FileTable.Entries) {
        byte[] bytes = entry.GetDecompressedData();
        string sha256;
        using (var hash = SHA256.Create())
            sha256 = string.Concat(hash.ComputeHash(bytes).Select(value => value.ToString("x2")));
        if (args.Length == 2) {
            string relative = entry.RelativePath.Replace('\\', Path.DirectorySeparatorChar);
            string root = Path.GetFullPath(args[1]) + Path.DirectorySeparatorChar;
            string local = Path.GetFullPath(Path.Combine(root, relative));
            if (!local.StartsWith(root, StringComparison.Ordinal))
                throw new InvalidDataException("Unsafe archive path: " + entry.RelativePath);
            if (!File.ReadAllBytes(local).SequenceEqual(bytes))
                throw new InvalidDataException("Content mismatch: " + entry.RelativePath);
        }
        Console.WriteLine(new JavaScriptSerializer().Serialize(new {
            path = entry.RelativePath,
            flags = (int)entry.Flags,
            size = bytes.Length,
            sha256
        }));
        checkedCount++;
    }
    Console.Error.WriteLine($"PASS GRFEditor: version {grf.Header.Version}, {checkedCount} entries read and hashed" +
        (args.Length == 2 ? ", all matched expected directory" : ""));
    return 0;
}
catch (Exception error) {
    Console.Error.WriteLine(error);
    return 1;
}
