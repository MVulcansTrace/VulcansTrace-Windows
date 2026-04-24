using System.Globalization;
using System.Text;
using VulcansTrace.Core;

namespace VulcansTrace.Evidence.Formatters;

/// <summary>
/// Formats analysis results as CSV (Comma-Separated Values).
/// </summary>
/// <remarks>
/// Produces RFC 4180-compliant CSV with proper quoting and escaping.
/// </remarks>
public sealed class CsvFormatter
{
    /// <summary>
    /// Converts analysis results to CSV format.
    /// </summary>
    /// <param name="result">The analysis result to format.</param>
    /// <returns>A string containing the findings in CSV format.</returns>
    public string ToCsv(AnalysisResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription");

        foreach (var f in result.Findings)
        {
            var fields = new[]
            {
                f.Category,
                f.Severity.ToString(),
                f.SourceHost,
                f.Target,
                f.TimeRangeStart.ToString("o", CultureInfo.InvariantCulture),
                f.TimeRangeEnd.ToString("o", CultureInfo.InvariantCulture),
                f.ShortDescription
            };

            sb.AppendLine(string.Join(",", fields.Select(Escape)));
        }

        if (result.Warnings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Warnings");
            foreach (var warning in result.Warnings)
            {
                sb.AppendLine(Escape(warning));
            }
        }

        return sb.ToString();
    }

    private static string Escape(string value)
    {
        if (value == null) return "";
        var sanitized = value;
        if (!string.IsNullOrEmpty(sanitized))
        {
            var first = sanitized[0];
            if (first == '=' || first == '+' || first == '-' || first == '@')
            {
                sanitized = "'" + sanitized;
            }
        }

        if (sanitized.Contains('"') || sanitized.Contains(',') || sanitized.Contains('\n') || sanitized.Contains('\r'))
        {
            var escaped = sanitized.Replace("\"", "\"\"");
            return $"\"{escaped}\"";
        }

        return sanitized;
    }
}
