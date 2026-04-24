using System.Linq;
using VulcansTrace.Core;
using VulcansTrace.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Tests.Evidence;

public class MarkdownFormatterTests
{
    [Fact]
    public void ToMarkdown_WithEmptyResult_ReturnsHeaderWithStats()
    {
        // Arrange
        var formatter = new MarkdownFormatter();
        var result = new AnalysisResult
        {
            TotalLines = 100,
            ParsedLines = 80,
            IgnoredLines = 20
        };

        // Act
        var markdown = formatter.ToMarkdown(result);

        // Assert
        Assert.Contains("# VulcansTrace Analysis Summary", markdown);
        Assert.Contains("* Total lines: 100", markdown);
        Assert.Contains("* Parsed lines: 80", markdown);
        Assert.Contains("* Ignored lines: 20", markdown);
        Assert.Contains("## Findings by Severity", markdown);
        Assert.Contains("## Findings", markdown);
    }

    [Fact]
    public void ToMarkdown_WithTimeRange_IncludesTimeRangeInSummary()
    {
        // Arrange
        var formatter = new MarkdownFormatter();
        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 0, 0)
        };

        // Act
        var markdown = formatter.ToMarkdown(result);

        // Assert
        Assert.Contains("2024-01-01T12:00:00.0000000", markdown);
        Assert.Contains("2024-01-01T13:00:00.0000000", markdown);
        Assert.Contains("* Time range:", markdown);
    }

    [Fact]
    public void ToMarkdown_WithFindings_IncludesSeverityCountsAndTable()
    {
        // Arrange
        var formatter = new MarkdownFormatter();
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
            Category = "Beaconing",
            Severity = Severity.Critical,
            SourceHost = "192.168.1.101",
            Target = "external:8080",
            TimeRangeStart = new DateTime(2024, 1, 1, 13, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 10, 0),
            ShortDescription = "Regular beaconing detected"
        });

        // Act
        var markdown = formatter.ToMarkdown(result);

        // Assert
        Assert.Contains("* Critical: 1", markdown);
        Assert.Contains("* High: 1", markdown);
        Assert.Contains("| PortScan | High | 192.168.1.100 |", markdown);
        Assert.Contains("| Beaconing | Critical | 192.168.1.101 |", markdown);
        Assert.Contains("| Category | Severity | Source | Target |", markdown);
    }

    [Fact]
    public void ToMarkdown_EscapesSpecialCharactersAndNewlines()
    {
        // Arrange
        var formatter = new MarkdownFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "Port|Scan",
            Severity = Severity.High,
            SourceHost = "srv\\core",
            Target = "external:80*80",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Desc with [link]\nand `code`"
        });

        // Act
        var markdown = formatter.ToMarkdown(result);

        // Assert
        Assert.DoesNotContain("Port|Scan", markdown); // should be escaped with backslash
        Assert.Contains("Port\\|Scan", markdown);
        Assert.Contains("srv\\\\core", markdown);
        Assert.Contains("external:80\\*80", markdown);
        Assert.Contains("\\[link\\]", markdown);
        Assert.Contains("<br>", markdown);
        Assert.Contains("\\`code\\`", markdown);
    }

    [Fact]
    public void ToMarkdown_WithWarnings_ListsWarnings()
    {
        var formatter = new MarkdownFormatter();
        var result = new AnalysisResult();
        result.AddWarning("Truncated to 5 events");

        var markdown = formatter.ToMarkdown(result);

        Assert.Contains("## Warnings", markdown);
        Assert.Contains("Truncated to 5 events", markdown);
        Assert.Contains("* Warnings: 1", markdown);
    }
}
