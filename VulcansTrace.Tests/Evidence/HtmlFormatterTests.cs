using VulcansTrace.Core;
using VulcansTrace.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Tests.Evidence;

public class HtmlFormatterTests
{
    [Fact]
    public void ToHtml_WithEmptyResult_ReturnsBasicHtmlStructure()
    {
        // Arrange
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            TotalLines = 100,
            ParsedLines = 80,
            IgnoredLines = 20
        };

        // Act
        var html = formatter.ToHtml(result);

        // Assert
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("<title>VulcansTrace Report</title>", html);
        Assert.Contains("<h1>VulcansTrace Analysis Report</h1>", html);
        Assert.Contains("<li>Total lines: 100</li>", html);
        Assert.Contains("<li>Parsed lines: 80</li>", html);
        Assert.Contains("<li>Ignored lines: 20</li>", html);
        Assert.Contains("<h2>Findings</h2>", html);
    }

    [Fact]
    public void ToHtml_WithTimeRange_IncludesTimeRangeInList()
    {
        // Arrange
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 0, 0)
        };

        // Act
        var html = formatter.ToHtml(result);

        // Assert
        Assert.Contains("2024-01-01T12:00:00.0000000", html);
        Assert.Contains("2024-01-01T13:00:00.0000000", html);
        Assert.Contains("<li>Time range:", html);
    }

    [Fact]
    public void ToHtml_WithFindings_IncludesTableRowsWithHtmlEncoding()
    {
        // Arrange
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Port scan detected"
        });
        result.AddFinding(new Finding
        {
            Category = "Test<Category>",
            Severity = Severity.Critical,
            SourceHost = "192.168.1.101",
            Target = "external:8080",
            TimeRangeStart = new DateTime(2024, 1, 1, 13, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 10, 0),
            ShortDescription = "Test with special chars: <>&\"'"
        });

        // Act
        var html = formatter.ToHtml(result);

        // Assert
        Assert.Contains("<th>Category</th>", html);
        Assert.Contains("<th>Severity</th>", html);
        Assert.Contains("<td>PortScan</td>", html);
        Assert.Contains("<td>High</td>", html);
        Assert.Contains("<td>192.168.1.100</td>", html);
        Assert.Contains("&lt;Category&gt;", html); // HTML encoding for special chars
        Assert.Contains("&lt;&gt;&amp;&quot;&#39;", html); // HTML encoding for special chars
        Assert.Contains("Critical", html);
        Assert.Contains("background:#111", html); // CSS styling present
        Assert.Contains("</body></html>", html);
    }

    [Fact]
    public void ToHtml_WithWarnings_RendersWarningList()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult();
        result.AddWarning("Port scan truncated");

        var html = formatter.ToHtml(result);

        Assert.Contains("<h2>Warnings</h2>", html);
        Assert.Contains("Port scan truncated", html);
        Assert.Contains("Warnings: 1", html);
    }

    [Fact]
    public void ToHtml_WithParseErrors_RendersParseErrorCount()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            ParseErrorCount = 42
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("Parse errors: 42", html);
    }
}
