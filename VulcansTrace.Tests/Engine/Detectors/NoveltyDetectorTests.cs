using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Detectors;
using VulcansTrace.Engine.Net;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine.Detectors;

public class NoveltyDetectorTests
{
    private readonly NoveltyDetector _detector = new();

    [Fact]
    public void Detect_WithOneOffExternalDestination_ReturnsFinding()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var externalIp = "203.0.113.50";
        var port = 443;

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = externalIp,
            DstPort = port,
            Direction = "OUTBOUND",
            RawLine = $"2024-01-01 12:00:00 ALLOW TCP {srcIp} 50000 {externalIp} {port} OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("Novelty", findings[0].Category);
        Assert.Equal(Severity.Low, findings[0].Severity);
        Assert.Equal(srcIp, findings[0].SourceHost);
        Assert.Equal($"{externalIp}:{port}", findings[0].Target);
        Assert.Contains("Novel external destination", findings[0].ShortDescription);
        Assert.Contains($"{externalIp}:{port}", findings[0].Details);
    }

    [Fact]
    public void Detect_WithRepeatedExternalDestination_ReturnsNoFindings()
    {
        // Arrange - Same external destination contacted multiple times
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var externalIp = "203.0.113.50";
        var port = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // Create 3 connections to the same external destination
        for (int i = 0; i < 3; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = externalIp,
                DstPort = port,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithNoveltyDisabled_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var externalIp = "203.0.113.50";
        var port = 443;

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = externalIp,
            DstPort = port,
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnableNovelty = false // Disabled
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
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithInternalTrafficOnly_ReturnsNoFindings()
    {
        // Arrange - All traffic is internal to internal
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        entries.Add(new LogEntry
        {
            Timestamp = baseTime,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.100",
            SrcPort = 50000,
            DstIp = "192.168.1.10",
            DstPort = 443,
            Direction = "INBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithMixedDestinations_ReturnsOnlyNovelFindings()
    {
        // Arrange - Mix of one-off and repeated external destinations
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // One-off destination 1 (should trigger)
        entries.Add(new LogEntry
        {
            Timestamp = baseTime,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.100",
            SrcPort = 50000,
            DstIp = "203.0.113.50",
            DstPort = 443,
            Direction = "OUTBOUND"
        });

        // One-off destination 2 (should trigger)
        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(1),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.101",
            SrcPort = 50001,
            DstIp = "203.0.113.60",
            DstPort = 8443,
            Direction = "OUTBOUND"
        });

        // Repeated destination (should not trigger)
        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(2),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.102",
            SrcPort = 50002,
            DstIp = "203.0.113.70",
            DstPort = 80,
            Direction = "OUTBOUND"
        });

        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(3),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.103",
            SrcPort = 50003,
            DstIp = "203.0.113.70",
            DstPort = 80,
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Target.Contains("203.0.113.50:443"));
        Assert.Contains(findings, f => f.Target.Contains("203.0.113.60:8443"));
        Assert.DoesNotContain(findings, f => f.Target.Contains("203.0.113.70:80"));
    }

    [Fact]
    public void Detect_WithSameIpDifferentPorts_ReturnsFindingsForEach()
    {
        // Arrange - Same external IP but different ports, each contacted once
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var externalIp = "203.0.113.50";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        entries.Add(new LogEntry
        {
            Timestamp = baseTime,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = externalIp,
            DstPort = 443,
            Direction = "OUTBOUND"
        });

        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(1),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50001,
            DstIp = externalIp,
            DstPort = 8080,
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Target == $"{externalIp}:443");
        Assert.Contains(findings, f => f.Target == $"{externalIp}:8080");
    }

    [Fact]
    public void Detect_WithDifferentIpSamePort_ReturnsFindingsForEach()
    {
        // Arrange - Different external IPs but same port, each contacted once
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var port = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        entries.Add(new LogEntry
        {
            Timestamp = baseTime,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = "203.0.113.50",
            DstPort = port,
            Direction = "OUTBOUND"
        });

        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(1),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50001,
            DstIp = "203.0.113.60",
            DstPort = port,
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Target == "203.0.113.50:443");
        Assert.Contains(findings, f => f.Target == "203.0.113.60:443");
    }
}