using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Detectors;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine.Detectors;

public class PortScanDetectorTests
{
    private readonly PortScanDetector _detector = new();

    [Fact]
    public void Detect_WithPortScanAboveThreshold_ReturnsFinding()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create 20 different destination ports from the same source within 5 minutes
        for (int port = 1000; port < 1020; port++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(port % 3), // Spread within 5-minute window
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = port,
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{port % 3:00}:00 ALLOW TCP {srcIp} 50000 10.0.0.1 {port} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("PortScan", findings[0].Category);
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Equal(srcIp, findings[0].SourceHost);
        Assert.Equal("multiple hosts/ports", findings[0].Target);
        Assert.Contains("Port scan detected", findings[0].ShortDescription);
        Assert.Contains("20 distinct destinations", findings[0].Details);
    }

    [Fact]
    public void Detect_WithPortScanBelowThreshold_ReturnsNoFindings()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create only 5 different destination ports (below threshold of 15)
        for (int port = 1000; port < 1005; port++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(port % 3),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = port,
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{port % 3:00}:00 ALLOW TCP {srcIp} 50000 10.0.0.1 {port} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithPortScanDisabled_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";

        // Create 20 different destination ports
        for (int port = 1000; port < 1020; port++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = DateTime.Now,
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = port,
                Direction = "INBOUND",
                RawLine = $"ALLOW TCP {srcIp} 50000 10.0.0.1 {port} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = false, // Disabled
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
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
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
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

        // First source with port scan
        for (int port = 1000; port < 1020; port++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(port % 3),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.100",
                SrcPort = 50000,
                DstIp = "10.0.0.1",
                DstPort = port,
                Direction = "INBOUND"
            });
        }

        // Second source with port scan
        for (int port = 2000; port < 2020; port++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(port % 3),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.101",
                SrcPort = 50001,
                DstIp = "10.0.0.2",
                DstPort = port,
                Direction = "INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.100");
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.101");
    }

    [Fact]
    public void Detect_WithTruncation_EmitsWarning()
    {
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 4, 1, 10, 0, 0);
        for (int i = 0; i < 10; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i),
                SrcIp = "10.0.0.1",
                DstIp = $"10.0.0.{i + 10}",
                DstPort = 1000 + i,
                SrcPort = 5000 + i,
                Protocol = "TCP",
                Action = "ALLOW",
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = 5
        };

        var detector = new PortScanDetector();

        var findings = detector.Detect(entries, profile, CancellationToken.None).ToList();

        Assert.Single(findings);
        var warnings = ((IProducesWarnings)detector).Warnings;
        Assert.Single(warnings);
        Assert.Contains("truncated to 5 events", warnings[0]);
    }

    [Fact]
    public void Detect_WithUnlimitedCap_DoesNotEmitWarning()
    {
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 4, 1, 10, 0, 0);
        for (int i = 0; i < 6; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i),
                SrcIp = "10.0.0.2",
                DstIp = $"10.0.1.{i + 1}",
                DstPort = 2000 + i,
                SrcPort = 6000 + i,
                Protocol = "TCP",
                Action = "ALLOW",
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = null
        };

        var detector = new PortScanDetector();

        var findings = detector.Detect(entries, profile, CancellationToken.None).ToList();

        Assert.Single(findings);
        var warnings = ((IProducesWarnings)detector).Warnings;
        Assert.Empty(warnings);
    }

    [Fact]
    public void Detect_WithZeroWindowMinutes_ThrowsArgumentOutOfRangeException()
    {
        var entries = new List<LogEntry>
        {
            new()
            {
                Timestamp = new DateTime(2024, 4, 1, 10, 0, 0),
                SrcIp = "10.0.0.3",
                DstIp = "10.0.1.1",
                DstPort = 2000,
                SrcPort = 6000,
                Protocol = "TCP",
                Action = "ALLOW",
                Direction = "OUTBOUND"
            }
        };

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 0
        };

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            _detector.Detect(entries, profile, CancellationToken.None).ToList());

        Assert.Equal("PortScanWindowMinutes", ex.ParamName);
    }
}
