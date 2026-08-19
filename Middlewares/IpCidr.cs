using System.Net;
using System.Net.Sockets;

namespace HanaMedia.Middlewares;

public readonly struct IpCidr
{
    public IPAddress Network { get; }

    public int PrefixLength { get; }

    private IpCidr(IPAddress network, int prefixLength)
    {
        Network = network;
        PrefixLength = prefixLength;
    }

    public static bool TryParse(string cidr, out IpCidr network)
    {
        network = default;

        if (string.IsNullOrWhiteSpace(cidr))
        {
            return false;
        }

        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out var baseAddress))
        {
            return false;
        }

        if (!int.TryParse(parts[1], out var prefix))
        {
            return false;
        }

        var maxPrefix = baseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > maxPrefix)
        {
            return false;
        }

        network = new IpCidr(baseAddress, prefix);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != Network.AddressFamily)
        {
            return false;
        }

        var networkBytes = Network.GetAddressBytes();
        var addressBytes = address.GetAddressBytes();

        var fullBytes = PrefixLength / 8;
        var remainingBits = PrefixLength % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            if (networkBytes[i] != addressBytes[i])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        if (fullBytes >= networkBytes.Length)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[fullBytes] & mask) == (addressBytes[fullBytes] & mask);
    }
}
