using System.Globalization;
using VulcansTrace.Wpf.Validation;

namespace VulcansTrace.Tests.Wpf;

public class NonNegativeIntValidationRuleTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("5")]
    [InlineData("0010")]
    public void Validate_WithNonNegativeIntegers_IsValid(string input)
    {
        var rule = new NonNegativeIntValidationRule();

        var result = rule.Validate(input, CultureInfo.InvariantCulture);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(100)]
    public void Validate_WithNonNegativeIntValue_IsValid(int input)
    {
        var rule = new NonNegativeIntValidationRule();

        var result = rule.Validate(input, CultureInfo.InvariantCulture);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Validate_WithNegativeIntValue_IsInvalid(int input)
    {
        var rule = new NonNegativeIntValidationRule();

        var result = rule.Validate(input, CultureInfo.InvariantCulture);

        Assert.False(result.IsValid);
        Assert.Equal("Enter a non-negative number.", result.ErrorContent);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void Validate_WithInvalidValues_IsInvalid(object? input)
    {
        var rule = new NonNegativeIntValidationRule();

        var result = rule.Validate(input!, CultureInfo.InvariantCulture);

        Assert.False(result.IsValid);
        Assert.Equal("Enter a non-negative number.", result.ErrorContent);
    }
}
