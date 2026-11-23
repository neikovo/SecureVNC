using System.Buffers.Binary;
using System.Text;

namespace SecureVNC.Shared.Protocol;

/// <summary>Big-endian blocking reader over a stream (one reader thread per connection).</summary>
public sealed class RfbReader(Stream stream)
{
    private readonly byte[] _b = new byte[8];

    public Stream Stream => stream;

    public void ReadExactly(Span<byte> buffer) => stream.ReadExactly(buffer);

    public byte[] ReadBytes(int count)
    {
        var b = new byte[count];
        stream.ReadExactly(b);
        return b;
    }

    public byte U8()
    {
        stream.ReadExactly(_b, 0, 1);
        return _b[0];
    }

    public ushort U16()
    {
        stream.ReadExactly(_b, 0, 2);
        return BinaryPrimitives.ReadUInt16BigEndian(_b);
    }

    public uint U32()
    {
        stream.ReadExactly(_b, 0, 4);
        return BinaryPrimitives.ReadUInt32BigEndian(_b);
    }

    public int S32()
    {
        stream.ReadExactly(_b, 0, 4);
        return BinaryPrimitives.ReadInt32BigEndian(_b);
    }

    public void Skip(long count)
    {
        Span<byte> tmp = stackalloc byte[512];
        while (count > 0)
        {
            int n = (int)Math.Min(count, tmp.Length);
            stream.ReadExactly(tmp[..n]);
            count -= n;
        }
    }

    /// <summary>Reads a u32-length-prefixed UTF-8 string, refusing anything longer than maxBytes.</summary>
    public string LengthPrefixedString(int maxBytes)
    {
        uint len = U32();
        if (len > maxBytes) throw new ProtocolException($"String too long ({len} bytes).");
        return Encoding.UTF8.GetString(ReadBytes((int)len));
    }
}
