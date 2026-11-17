using System.Security.Cryptography;
using System.Text;

namespace Keelie;

/// <summary>The name-based UUID of RFC 9562, version 5 (SHA-1), as Python's <c>uuid.uuid5</c> makes it.</summary>
internal static class Uuid5
{
    internal static Guid Create(Guid ns, string name)
    {
        // The namespace in network byte order, as RFC 9562 and Python read it. A Guid's own byte
        // array is little-endian in its first three fields.
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var input = new byte[16 + nameBytes.Length];
        ns.TryWriteBytes(input.AsSpan(0, 16), bigEndian: true, out _);
        nameBytes.CopyTo(input, 16);
#pragma warning disable CA5350 // SHA-1 is what UUIDv5 is defined with. It is a name, not a signature.
        var hash = SHA1.HashData(input);
#pragma warning restore CA5350
        var bytes = hash.AsSpan(0, 16);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes, bigEndian: true);
    }
}
