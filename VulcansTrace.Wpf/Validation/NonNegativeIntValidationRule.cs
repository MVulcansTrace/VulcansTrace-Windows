using System.Globalization;
using System.Windows.Controls;

namespace VulcansTrace.Wpf.Validation;

public sealed class NonNegativeIntValidationRule : ValidationRule
{
    public override ValidationResult Validate(object value, CultureInfo cultureInfo)
    {
        if (value is int intValue)
        {
            return intValue >= 0
                ? ValidationResult.ValidResult
                : new ValidationResult(false, "Enter a non-negative number.");
        }

        if (value is string s && int.TryParse(s, NumberStyles.Integer, cultureInfo, out var result) && result >= 0)
        {
            return ValidationResult.ValidResult;
        }

        return new ValidationResult(false, "Enter a non-negative number.");
    }
}
