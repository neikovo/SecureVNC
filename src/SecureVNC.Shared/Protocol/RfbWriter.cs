using System.Buffers.Binary;
using System.Text;

namespace SecureVNC.Shared.Protocol;

/// <summary>Growable big-endian message builder; a message is built fully, then written in one call.</summary>
public sealed class RfbWriter
{
    private byte[] _buf = new byte[256];
    private int _len;

    public int Length => _len;
    public ReadOnlySpan<byte> Span => _buf.AsSpan(0, _len);

    public RfbWriter Reset()
    {
        _len = 0;
        return this;
    }

    private void Ensure(int n)
    {
        if (_len + n > _buf.Length)
            Array.Resize(ref _buf, Math.Max(_buf.Length * 2, _len + n));
    }

    public RfbWriter U8(byte v)
    {
        Ensure(1);
        _buf[_len++] = v;
        return this;
    }

    public RfbWriter U16(ushort v)
    {
        Ensure(2);
        BinaryPrimitives.WriteUInt16BigEndian(_buf.AsSpan(_len), v);
        _len += 2;
        return this;
    }

    public RfbWriter U32(uint v)
    {
        Ensure(4);
        BinaryPrimitives.WriteUInt32BigEndian(_buf.AsSpan(_len), v);
        _len += 4;
        return this;
    }

    public RfbWriter S32(int v)
    {
        Ensure(4);
        BinaryPrimitives.WriteInt32BigEndian(_buf.AsSpan(_len), v);
        _len += 4;
        return this;
    }

    public RfbWriter Bytes(ReadOnlySpan<byte> data)
    {
        Ensure(data.Length);
        data.CopyTo(_buf.AsSpan(_len));
        _len += data.Length;
        return this;
    }

    public RfbWriter LengthPrefixedString(string s)
    {
        var b = Encoding.UTF8.GetBytes(s);
        return U32((uint)b.Length).Bytes(b);
    }

    public void WriteTo(Stream s)
    {
        s.Write(_buf, 0, _len);
        s.Flush();
    }
}
