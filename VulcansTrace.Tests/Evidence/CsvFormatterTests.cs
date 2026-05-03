using VulcansTrace.Core;
using VulcansTrace.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Tests.Evidence;

public class CsvFormatterTests
{
    [Fact]
    public void ToCsv_WithEmptyResult_ReturnsHeaderOnly()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Single(lines);
        Assert.Equal("Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription", lines[0]);
    }

    [Fact]
    public void ToCsv_WithSingleFinding_ReturnsHeaderPlusOneLine()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "TestCategory",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.1:443",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Test finding description"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Equal("Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription", lines[0]);
        Assert.Contains("TestCategory", lines[1]);
        Assert.Contains("High", lines[1]);
        Assert.Contains("192.168.1.100", lines[1]);
    }

    [Fact]
    public void ToCsv_WithMultipleFindings_ReturnsHeaderPlusMultipleLines()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
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
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length); // Header + 2 findings
        Assert.Contains("PortScan", lines[1]);
        Assert.Contains("Beaconing", lines[2]);
    }

    [Fact]
    public void ToCsv_WithCommaInField_EscapesWithQuotes()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "Test,Category",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Description"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains("\"Test,Category\"", lines[1]);
    }

    [Fact]
    public void ToCsv_WithQuoteInField_EscapesWithDoubleQuotes()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "TestCategory",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Description with \"quotes\""
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains("\"Description with \"\"quotes\"\"\"", lines[1]);
    }

    [Fact]
    public void ToCsv_WithNewlineInField_EscapesWithQuotes()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "TestCategory",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Description with\nnewline"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        Assert.Contains("Description with\nnewline", csv);
        Assert.Contains("\"Description with\nnewline\"", csv); // Should be quoted due to newline
    }

    [Theory]
    [InlineData("=1+1")]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData("@cmd")]
    public void ToCsv_WithFormulaLeadingValue_PrefixesApostrophe(string value)
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = value,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Description"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains($"'{value}", lines[1]);
    }

    [Theory]
    [InlineData(" =1+1")]
    [InlineData("\t+1")]
    [InlineData(" \t@cmd")]
    public void ToCsv_WithFormulaAfterLeadingWhitespace_PrefixesApostrophe(string value)
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = value,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Description"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        Assert.Contains($"'{value}", csv);
    }

    [Fact]
    public void ToCsv_WithNullField_ReturnsEmpty()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Description"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains(",High,192.168.1.100", lines[1]); // Empty category field
    }

    [Fact]
    public void ToCsv_WithDateTime_FormatUsesISO8601()
    {
        // Arrange
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "Test",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0, DateTimeKind.Utc),
            ShortDescription = "Description"
        });

        // Act
        var csv = formatter.ToCsv(result);

        // Assert
        var lines = csv.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains("2024-01-01T12:00:00.0000000Z", lines[1]);
        Assert.Contains("2024-01-01T12:05:00.0000000Z", lines[1]);
    }

    [Fact]
    public void ToCsv_WithWarnings_AppendsWarningsSection()
    {
        var formatter = new CsvFormatter();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "Test",
            Severity = Severity.High,
            SourceHost = "src",
            Target = "dst",
            TimeRangeStart = new DateTime(2024, 1, 1, 1, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2024, 1, 1, 1, 5, 0, DateTimeKind.Utc),
            ShortDescription = "desc"
        });
        result.AddWarning("Truncated to 5 events");

        var csv = formatter.ToCsv(result);

        Assert.Contains("Warnings", csv);
        Assert.Contains("Truncated to 5 events", csv);
        Assert.Contains("Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription", csv);
    }
}
