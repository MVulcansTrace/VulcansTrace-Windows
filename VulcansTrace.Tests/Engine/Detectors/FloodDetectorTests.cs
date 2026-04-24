using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Detectors;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine.Detectors;

public class FloodDetectorTests
{
    private readonly FloodDetector _detector = new();

    [Fact]
    public void Detect_WithFloodAboveThreshold_ReturnsFinding()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create 250 events from the same source within 60 seconds (above threshold of 200)
        for (int i = 0; i < 250; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMilliseconds(i * 200), // 200ms intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND",
                RawLine = $"2024-01-01 12:00:{i:D2} ALLOW TCP {srcIp} 50000 10.0.0.1 80 OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("Flood", findings[0].Category);
        Assert.Equal(Severity.High, findings[0].Severity);
        Assert.Equal(srcIp, findings[0].SourceHost);
        Assert.Equal("multiple hosts/ports", findings[0].Target);
        Assert.Contains("Flood detected", findings[0].ShortDescription);
        Assert.Contains("events within 60 seconds", findings[0].Details);
    }

    [Fact]
    public void Detect_WithFloodBelowThreshold_ReturnsNoFindings()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create only 50 events from the same source within 60 seconds (below threshold of 200)
        for (int i = 0; i < 50; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND",
                RawLine = $"2024-01-01 12:00:{i:D2} ALLOW TCP {srcIp} 50000 10.0.0.1 80 OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithFloodDisabled_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";

        // Create 250 events that would normally trigger a flood
        for (int i = 0; i < 250; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = DateTime.Now.AddMilliseconds(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND",
                RawLine = $"ALLOW TCP {srcIp} 50000 10.0.0.1 80 OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = false, // Disabled
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithEmptyLog_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithMultipleSourceIps_ReturnsFindingsForEach()
    {
        // Arrange
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);
        var entries = new List<LogEntry>();

        // First source with flood
        for (int i = 0; i < 250; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMilliseconds(i * 100),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.100",
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND"
            });
        }

        // Second source with flood
        for (int i = 0; i < 220; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMilliseconds(i * 150),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.101",
                SrcPort = 50001,
                DstIp = "10.0.0.2",
                DstPort = 443,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.100");
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.101");
    }

    [Fact]
    public void Detect_WithEventsSpreadOutOverTime_ReturnsNoFindings()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create 250 events but spread them over 2 minutes (outside 60-second window)
        for (int i = 0; i < 250; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMilliseconds(i * 500), // 500ms intervals = 125 seconds total
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND",
                RawLine = $"2024-01-01 12:{i/120:D2}:{(i%120):D2} ALLOW TCP {srcIp} 50000 10.0.0.1 80 OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WhenExactlyAtThreshold_CreatesFinding()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create exactly 200 events (at threshold) within 60 seconds
        for (int i = 0; i < 200; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMilliseconds(i * 200), // 200ms intervals = 40 seconds total
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND",
                RawLine = $"2024-01-01 12:00:{i:D2} ALLOW TCP {srcIp} 50000 10.0.0.1 80 OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("Flood", findings[0].Category);
        Assert.Equal(srcIp, findings[0].SourceHost);
    }

    [Fact]
    public void Detect_WhenOneBelowThreshold_ReturnsNoFindings()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create 199 events (one below threshold of 200) within 60 seconds
        for (int i = 0; i < 199; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMilliseconds(i * 200), // 200ms intervals = ~40 seconds total
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = 80,
                Direction = "OUTBOUND",
                RawLine = $"2024-01-01 12:00:{i:D2} ALLOW TCP {srcIp} 50000 10.0.0.1 80 OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 200,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }
}