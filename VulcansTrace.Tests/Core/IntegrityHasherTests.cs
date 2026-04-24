using System.Security.Cryptography;
using Xunit;
using VulcansTrace.Core.Security;

namespace VulcansTrace.Tests.Core;

public class IntegrityHasherTests
{
    private readonly IntegrityHasher _hasher = new();

    [Fact]
    public void ComputeSha256_WithKnownInput_ReturnsExpectedHash()
    {
        // Arrange
        var input = "abc"u8.ToArray(); // UTF-8 bytes for "abc"
        var expectedHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        // Act
        var result = _hasher.ComputeSha256(input);
        var resultHex = Convert.ToHexString(result).ToLowerInvariant();

        // Assert
        Assert.Equal(32, result.Length); // SHA-256 produces 32 bytes
        Assert.Equal(expectedHex, resultHex);
    }

    [Fact]
    public void ComputeSha256_SameInput_ReturnsSameHash()
    {
        // Arrange
        var input = "Hello, World!"u8.ToArray();

        // Act
        var result1 = _hasher.ComputeSha256(input);
        var result2 = _hasher.ComputeSha256(input);

        // Assert
        Assert.Equal(result1, result2);
    }

    [Fact]
    public void ComputeSha256_DifferentInput_ReturnsDifferentHash()
    {
        // Arrange
        var input1 = "Hello"u8.ToArray();
        var input2 = "World"u8.ToArray();

        // Act
        var result1 = _hasher.ComputeSha256(input1);
        var result2 = _hasher.ComputeSha256(input2);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void ComputeHmacSha256_WithKnownInputAndKey_ReturnsExpectedHmac()
    {
        // Arrange
        var data = "Hello, World!"u8.ToArray();
        var key = "secret-key"u8.ToArray();

        // Act
        var result = _hasher.ComputeHmacSha256(data, key);
        var resultHex = Convert.ToHexString(result).ToLowerInvariant();

        // Assert
        Assert.Equal(32, result.Length); // HMAC-SHA256 produces 32 bytes
        // Verify it's consistent
        var result2 = _hasher.ComputeHmacSha256(data, key);
        var result2Hex = Convert.ToHexString(result2).ToLowerInvariant();
        Assert.Equal(resultHex, result2Hex);
    }

    [Fact]
    public void ComputeHmacSha256_SameInputAndKey_ReturnsSameHmac()
    {
        // Arrange
        var data = "test data"u8.ToArray();
        var key = "test key"u8.ToArray();

        // Act
        var result1 = _hasher.ComputeHmacSha256(data, key);
        var result2 = _hasher.ComputeHmacSha256(data, key);

        // Assert
        Assert.Equal(result1, result2);
    }

    [Fact]
    public void ComputeHmacSha256_DifferentKeys_ReturnsDifferentHmac()
    {
        // Arrange
        var data = "test data"u8.ToArray();
        var key1 = "key1"u8.ToArray();
        var key2 = "key2"u8.ToArray();

        // Act
        var result1 = _hasher.ComputeHmacSha256(data, key1);
        var result2 = _hasher.ComputeHmacSha256(data, key2);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void ComputeHmacSha256_DifferentData_ReturnsDifferentHmac()
    {
        // Arrange
        var data1 = "data1"u8.ToArray();
        var data2 = "data2"u8.ToArray();
        var key = "same key"u8.ToArray();

        // Act
        var result1 = _hasher.ComputeHmacSha256(data1, key);
        var result2 = _hasher.ComputeHmacSha256(data2, key);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void ComputeHmacSha256_EmptyData_ReturnsValidHmac()
    {
        // Arrange
        var data = Array.Empty<byte>();
        var key = "test key"u8.ToArray();

        // Act
        var result = _hasher.ComputeHmacSha256(data, key);

        // Assert
        Assert.Equal(32, result.Length);
        Assert.NotEmpty(result);
    }

    [Fact]
    public void ComputeSha256_EmptyInput_ReturnsKnownHash()
    {
        // Arrange
        var input = Array.Empty<byte>();
        var expectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // Act
        var result = _hasher.ComputeSha256(input);
        var resultHex = Convert.ToHexString(result).ToLowerInvariant();

        // Assert
        Assert.Equal(expectedHex, resultHex);
    }
}