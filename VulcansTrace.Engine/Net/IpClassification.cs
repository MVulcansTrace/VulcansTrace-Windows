using System.Net;

namespace VulcansTrace.Engine.Net;

public static class IpClassification
{
    public static bool IsInternal(string ip)
    {
        return TryClassify(ip, out var isInternal) && isInternal;
    }

    public static bool IsExternal(string ip) => TryClassify(ip, out var isInternal) && !isInternal;

    public static bool TryClassify(string ip, out bool isInternal)
    {
        if (!IPAddress.TryParse(ip, out var addr))
        {
            isInternal = false;
            return false;
        }

        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            isInternal = IsInternalV6(addr);
            return true;
        }

        // IPv4 or mapped IPv4
        if (addr.IsIPv4MappedToIPv6)
            addr = addr.MapToIPv4();

        var b = addr.GetAddressBytes();
        isInternal = b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || b[0] == 127;
        return true;
    }

    private static bool IsInternalV6(IPAddress addr)
    {
        // Loopback
        if (IPAddress.IPv6Loopback.Equals(addr))
            return true;

        // IPv4-mapped
        if (addr.IsIPv4MappedToIPv6)
            return IsInternal(addr.MapToIPv4().ToString());

        var bytes = addr.GetAddressBytes();

        // Unique Local Address fc00::/7 (0b1111110x)
        if ((bytes[0] & 0xFE) == 0xFC)
            return true;

        // Link-local fe80::/10 (1111 1110 10xx xxxx)
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
            return true;

        return false;
    }
}
