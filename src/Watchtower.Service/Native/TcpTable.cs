using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Native;

public sealed record TcpRow(int Pid, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, bool Listening, bool Established);

/// <summary>The TCP connection table with owning process IDs, read directly from the IP Helper API.</summary>
public static class TcpTable
{
    public static IReadOnlyList<TcpRow> Read()
    {
        var rows = new List<TcpRow>();
        ReadFamily(AF_INET, rows);
        ReadFamily(AF_INET6, rows);
        return rows;
    }

    private static unsafe void ReadFamily(int family, List<TcpRow> rows)
    {
        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            size += 4096;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var rc = GetExtendedTcpTable(buffer, ref size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc == 122) continue; // ERROR_INSUFFICIENT_BUFFER: table grew between calls
                if (rc != 0) return;

                var count = Marshal.ReadInt32(buffer);
                var first = buffer + 4;
                if (family == AF_INET)
                {
                    var p = (MIB_TCPROW_OWNER_PID*)first;
                    for (var i = 0; i < count; i++)
                    {
                        var r = p[i];
                        rows.Add(new TcpRow(r.OwningPid,
                            new IPAddress(r.LocalAddr).ToString(), Port(r.LocalPort),
                            new IPAddress(r.RemoteAddr).ToString(), Port(r.RemotePort),
                            r.State == MIB_TCP_STATE_LISTEN, r.State == MIB_TCP_STATE_ESTAB));
                    }
                }
                else
                {
                    var p = (MIB_TCP6ROW_OWNER_PID*)first;
                    for (var i = 0; i < count; i++)
                    {
                        var r = p[i];
                        rows.Add(new TcpRow(r.OwningPid,
                            V6(r.LocalAddr), Port(r.LocalPort),
                            V6(r.RemoteAddr), Port(r.RemotePort),
                            r.State == MIB_TCP_STATE_LISTEN, r.State == MIB_TCP_STATE_ESTAB));
                    }
                }
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static unsafe string V6(byte* bytes)
    {
        var ip = new IPAddress(new ReadOnlySpan<byte>(bytes, 16));
        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    // Ports are stored in network byte order in the low 16 bits.
    private static int Port(uint raw) => BinaryPrimitives.ReverseEndianness((ushort)(raw & 0xFFFF));
}
