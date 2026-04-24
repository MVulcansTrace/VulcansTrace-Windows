using Xunit;
using VulcansTrace.Core;

namespace VulcansTrace.Tests.Core;

public class CoreModelsTests
{
    [Fact]
    public void CanCreateSeverityEnum()
    {
        // Arrange & Act
        var severity = Severity.High;

        // Assert
        Assert.Equal(Severity.High, severity);
        Assert.True(severity >= Severity.Low && severity <= Severity.Critical);
    }

    [Fact]
    public void CanCreateLogEntry()
    {
        // Arrange
        var timestamp = DateTime.UtcNow;

        // Act
        var entry = new LogEntry
        {
            Timestamp = timestamp,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.100",
            SrcPort = 12345,
            DstIp = "10.0.0.1",
            DstPort = 445,
            PacketSize = 60,
            Path = "SEND",
            Direction = "SEND",
            RawLine = "2025-01-01 12:00:00 ALLOW TCP 192.168.1.100 10.0.0.1 12345 445 SEND"
        };

        // Assert
        Assert.Equal(timestamp, entry.Timestamp);
        Assert.Equal("ALLOW", entry.Action);
        Assert.Equal("TCP", entry.Protocol);
        Assert.Equal("192.168.1.100", entry.SrcIp);
        Assert.Equal(12345, entry.SrcPort);
        Assert.Equal("10.0.0.1", entry.DstIp);
        Assert.Equal(445, entry.DstPort);
        Assert.Equal(60, entry.PacketSize);
        Assert.Equal("SEND", entry.Path);
        Assert.Equal("SEND", entry.Direction);
        Assert.Equal("2025-01-01 12:00:00 ALLOW TCP 192.168.1.100 10.0.0.1 12345 445 SEND", entry.RawLine);
    }

    [Fact]
    public void CanCreateFinding()
    {
        // Arrange
        var timeStart = DateTime.UtcNow.AddHours(-1);
        var timeEnd = DateTime.UtcNow;

        // Act
        var finding = new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "Internal Network",
            TimeRangeStart = timeStart,
            TimeRangeEnd = timeEnd,
            ShortDescription = "Port scan detected",
            Details = "Multiple ports scanned from single source"
        };

        // Assert
        Assert.NotEqual(Guid.Empty, finding.Id);
        Assert.Equal("PortScan", finding.Category);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("192.168.1.100", finding.SourceHost);
        Assert.Equal("Internal Network", finding.Target);
        Assert.Equal(timeStart, finding.TimeRangeStart);
        Assert.Equal(timeEnd, finding.TimeRangeEnd);
        Assert.Equal("Port scan detected", finding.ShortDescription);
        Assert.Equal("Multiple ports scanned from single source", finding.Details);
    }

    [Fact]
    public void CanCreateAnalysisResult()
    {
        // Arrange
        var entry = new LogEntry
        {
            Timestamp = DateTime.UtcNow,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.100",
            SrcPort = 12345,
            DstIp = "10.0.0.1",
            DstPort = 445,
            Direction = "SEND"
        };

        var finding = new Finding
        {
            Category = "PolicyViolation",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "External Server:445"
        };

        // Act
        var result = new AnalysisResult
        {
            TotalLines = 100,
            ParsedLines = 95,
            IgnoredLines = 5,
            TimeRangeStart = DateTime.UtcNow.AddHours(-2),
            TimeRangeEnd = DateTime.UtcNow
        };

        result.AddEntry(entry);
        result.AddFinding(finding);

        // Assert
        Assert.Equal(100, result.TotalLines);
        Assert.Equal(95, result.ParsedLines);
        Assert.Equal(5, result.IgnoredLines);
        Assert.Single(result.Entries);
        Assert.Single(result.Findings);
        Assert.NotNull(result.TimeRangeStart);
        Assert.NotNull(result.TimeRangeEnd);
    }
}
