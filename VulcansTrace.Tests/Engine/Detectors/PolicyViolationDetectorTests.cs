using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Detectors;
using VulcansTrace.Engine.Net;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine.Detectors;

public class PolicyViolationDetectorTests
{
    private readonly PolicyViolationDetector _detector = new();

    [Fact]
    public void Detect_WithPolicyViolation_ReturnsFinding()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100"; // Internal IP
        var dstIp = "203.0.113.50"; // External IP
        var disallowedPort = 21; // FTP

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = dstIp,
            DstPort = disallowedPort,
            Direction = "OUTBOUND",
            RawLine = $"2024-01-01 12:00:00 ALLOW TCP {srcIp} 50000 {dstIp} {disallowedPort} OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 445 } // FTP, Telnet, SMB
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("PolicyViolation", findings[0].Category);
        Assert.Equal(Severity.High, findings[0].Severity);
        Assert.Equal(srcIp, findings[0].SourceHost);
        Assert.Equal($"{dstIp}:{disallowedPort}", findings[0].Target);
        Assert.Contains("Disallowed outbound port", findings[0].ShortDescription);
        Assert.Contains($"{dstIp}:{disallowedPort}", findings[0].Details);
    }

    [Fact]
    public void Detect_WithAllowedPort_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100"; // Internal IP
        var dstIp = "203.0.113.50"; // External IP
        var allowedPort = 443; // HTTPS

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = dstIp,
            DstPort = allowedPort,
            Direction = "OUTBOUND",
            RawLine = $"2024-01-01 12:00:00 ALLOW TCP {srcIp} 50000 {dstIp} {allowedPort} OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 445 } // FTP, Telnet, SMB
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithPolicyDisabled_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100"; // Internal IP
        var dstIp = "203.0.113.50"; // External IP
        var disallowedPort = 21; // FTP

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = dstIp,
            DstPort = disallowedPort,
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = false, // Disabled
            DisallowedOutboundPorts = new[] { 21, 23, 445 }
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
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 445 }
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithExternalToInternalTraffic_ReturnsNoFindings()
    {
        // Arrange - External to internal traffic should not trigger policy violation
        var entries = new List<LogEntry>();
        var srcIp = "203.0.113.100"; // External IP
        var dstIp = "192.168.1.10"; // Internal IP
        var disallowedPort = 445;

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = dstIp,
            DstPort = disallowedPort,
            Direction = "INBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 445 }
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithInternalToInternalTraffic_ReturnsNoFindings()
    {
        // Arrange - Internal to internal traffic should not trigger policy violation
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100"; // Internal IP
        var dstIp = "192.168.1.10"; // Internal IP
        var disallowedPort = 445;

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = dstIp,
            DstPort = disallowedPort,
            Direction = "INBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 445 }
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithMultipleViolations_ReturnsFindingsForEach()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // First violation - FTP
        entries.Add(new LogEntry
        {
            Timestamp = baseTime,
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.100",
            SrcPort = 50000,
            DstIp = "203.0.113.50",
            DstPort = 21, // FTP
            Direction = "OUTBOUND"
        });

        // Second violation - Telnet
        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(1),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.101",
            SrcPort = 50001,
            DstIp = "203.0.113.60",
            DstPort = 23, // Telnet
            Direction = "OUTBOUND"
        });

        // Third violation - SMB
        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(2),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = "192.168.1.102",
            SrcPort = 50002,
            DstIp = "203.0.113.70",
            DstPort = 445, // SMB
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 445 }
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(3, findings.Count);
        Assert.Contains(findings, f => f.Target.Contains(":21")); // FTP
        Assert.Contains(findings, f => f.Target.Contains(":23")); // Telnet
        Assert.Contains(findings, f => f.Target.Contains(":445")); // SMB
    }

    [Fact]
    public void Detect_WithEmptyDisallowedPortsList_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100"; // Internal IP
        var dstIp = "203.0.113.50"; // External IP
        var port = 21;

        entries.Add(new LogEntry
        {
            Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = dstIp,
            DstPort = port,
            Direction = "OUTBOUND"
        });

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = Array.Empty<int>() // No disallowed ports
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithNullDisallowedPorts_ReturnsNoFindings()
    {
        // Arrange - Tests defensive null-coalescing pattern
        var entries = new List<LogEntry>
        {
            new LogEntry
            {
                Timestamp = new DateTime(2024, 1, 1, 12, 0, 0),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.100", // Internal IP
                SrcPort = 50000,
                DstIp = "203.0.113.50", // External IP
                DstPort = 21, // Would be disallowed if configured
                Direction = "OUTBOUND"
            }
        };

        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = null! // Explicitly null to test defensive pattern
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert - No crash, no false positives
        Assert.Empty(findings);
    }
}