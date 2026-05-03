using VulcansTrace.Engine.Net;

namespace VulcansTrace.Tests.Engine;

public class IpClassificationTests
{
    [Fact]
    public void IsInternal_With10PrivateNetwork_ReturnsTrue()
    {
        // Arrange
        var ip = "10.0.0.1";

        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsInternal_With17216PrivateNetwork_ReturnsTrue()
    {
        // Arrange
        var ip = "172.16.5.10";

        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsInternal_With17231PrivateNetwork_ReturnsTrue()
    {
        // Arrange
        var ip = "172.31.255.255";

        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsInternal_With192168PrivateNetwork_ReturnsTrue()
    {
        // Arrange
        var ip = "192.168.1.5";

        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsInternal_WithPublicGoogleDns_ReturnsFalse()
    {
        // Arrange
        var ip = "8.8.8.8";

        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsExternal_WithPublicIp_ReturnsTrue()
    {
        // Arrange
        var ip = "1.1.1.1";

        // Act
        var result = IpClassification.IsExternal(ip);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsExternal_WithInternalIp_ReturnsFalse()
    {
        // Arrange
        var ip = "10.10.10.10";

        // Act
        var result = IpClassification.IsExternal(ip);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("172.15.255.255")] // Just below the 172.16.0.0/12 range
    [InlineData("172.32.0.0")] // Just above the 172.16.0.0/12 range
    [InlineData("192.167.255.255")] // Just below the 192.168.0.0/16 range
    [InlineData("192.169.0.0")] // Just above the 192.168.0.0/16 range
    [InlineData("9.255.255.255")] // Just below the 10.0.0.0/8 range
    [InlineData("11.0.0.0")] // Just above the 10.0.0.0/8 range
    public void IsInternal_WithPrivateRangeBoundaries_ReturnsFalse(string ip)
    {
        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData("not.an.ip.address")]
    [InlineData("256.256.256.256")]
    [InlineData("300.1.1.1")] // Invalid octet > 255
    public void IsInternal_WithInvalidIp_ReturnsFalse(string ip)
    {
        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsExternal_WithInvalidIp_ReturnsFalse()
    {
        var ip = "invalid.ip";

        var result = IpClassification.IsExternal(ip);

        Assert.False(result);
    }

    [Theory]
    [InlineData("::1")] // loopback
    [InlineData("fd00::1")] // ULA
    [InlineData("fd12:3456:789a::1")]
    [InlineData("fe80::1")] // link-local
    [InlineData("fe80::abcd:ef12:3456:789a")]
    public void IsInternal_WithIpv6InternalRanges_ReturnsTrue(string ip)
    {
        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.True(result);
    }

    [Theory]
    [InlineData("2001:4860:4860::8888")] // Google DNS v6
    [InlineData("2606:4700:4700::1111")] // Cloudflare v6
    [InlineData("2a00:1450::1")] // Global unicast
    public void IsInternal_WithGlobalIpv6_ReturnsFalse(string ip)
    {
        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsExternal_WithGlobalIpv6_ReturnsTrue()
    {
        var ip = "2606:4700:4700::1111";

        var result = IpClassification.IsExternal(ip);

        Assert.True(result);
    }

    [Theory]
    [InlineData("::ffff:192.168.1.1", true)] // mapped private
    [InlineData("::ffff:10.0.0.1", true)] // mapped private
    [InlineData("::ffff:8.8.8.8", false)] // mapped public
    public void IsInternal_WithIpv4MappedIpv6_RespectsMappedRange(string ip, bool expected)
    {
        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.50")]
    [InlineData("127.255.255.255")]
    public void IsInternal_WithIpv4Loopback_ReturnsTrue(string ip)
    {
        // Act
        var result = IpClassification.IsInternal(ip);

        // Assert
        Assert.True(result);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.50")]
    public void IsExternal_WithIpv4Loopback_ReturnsFalse(string ip)
    {
        // Act
        var result = IpClassification.IsExternal(ip);

        // Assert
        Assert.False(result);
    }
}
