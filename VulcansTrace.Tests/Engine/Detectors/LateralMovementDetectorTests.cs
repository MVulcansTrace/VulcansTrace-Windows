using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Detectors;
using VulcansTrace.Engine.Net;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine.Detectors;

public class LateralMovementDetectorTests
{
    private readonly LateralMovementDetector _detector = new();

    [Fact]
    public void Detect_WithLateralMovementAboveThreshold_ReturnsFinding()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create connections to 8 different internal hosts on admin ports (above threshold of 6)
        var targetHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
                                 "192.168.1.14", "192.168.1.15", "192.168.1.16", "192.168.1.17" };
        var adminPorts = new[] { 445, 3389, 22 };

        for (int i = 0; i < targetHosts.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = targetHosts[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{i:D2}:00 ALLOW TCP {srcIp} 50000 {targetHosts[i]} {adminPorts[i % adminPorts.Length]} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = adminPorts.ToList()
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("LateralMovement", findings[0].Category);
        Assert.Equal(Severity.High, findings[0].Severity);
        Assert.Equal(srcIp, findings[0].SourceHost);
        Assert.Equal("multiple internal hosts", findings[0].Target);
        Assert.Contains("Lateral movement from", findings[0].ShortDescription);
        Assert.Contains("internal hosts on admin ports", findings[0].Details);
    }

    [Fact]
    public void Detect_WithLateralMovementBelowThreshold_ReturnsNoFindings()
    {
        // Arrange
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();

        // Create connections to only 3 different internal hosts (below threshold of 6)
        var targetHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12" };
        var adminPorts = new[] { 445, 3389, 22 };

        for (int i = 0; i < targetHosts.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = targetHosts[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{i:D2}:00 ALLOW TCP {srcIp} 50000 {targetHosts[i]} {adminPorts[i % adminPorts.Length]} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = adminPorts.ToList()
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithLateralMovementDisabled_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";

        // Create connections that would normally trigger lateral movement detection
        var targetHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
                                 "192.168.1.14", "192.168.1.15", "192.168.1.16", "192.168.1.17" };
        var adminPorts = new[] { 445, 3389, 22 };

        for (int i = 0; i < targetHosts.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = DateTime.Now.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = targetHosts[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND",
                RawLine = $"ALLOW TCP {srcIp} 50000 {targetHosts[i]} {adminPorts[i % adminPorts.Length]} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = false, // Disabled
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = adminPorts.ToList()
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
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 445, 3389, 22 }.ToList()
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithExternalToInternalTraffic_ReturnsNoFindings()
    {
        // Arrange - External IP scanning internal hosts should not trigger lateral movement
        var entries = new List<LogEntry>();
        var srcIp = "203.0.113.100"; // External IP
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var targetHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
                                 "192.168.1.14", "192.168.1.15", "192.168.1.16", "192.168.1.17" };
        var adminPorts = new[] { 445, 3389, 22 };

        for (int i = 0; i < targetHosts.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = targetHosts[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{i:D2}:00 ALLOW TCP {srcIp} 50000 {targetHosts[i]} {adminPorts[i % adminPorts.Length]} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = adminPorts.ToList()
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithNonAdminPorts_ReturnsNoFindings()
    {
        // Arrange - Internal to internal traffic but on non-admin ports
        var srcIp = "192.168.1.100";
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        var entries = new List<LogEntry>();
        var targetHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
                                 "192.168.1.14", "192.168.1.15", "192.168.1.16", "192.168.1.17" };
        var nonAdminPorts = new[] { 80, 443, 8080 }; // Not admin ports

        for (int i = 0; i < targetHosts.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = targetHosts[i],
                DstPort = nonAdminPorts[i % nonAdminPorts.Length],
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{i:D2}:00 ALLOW TCP {srcIp} 50000 {targetHosts[i]} {nonAdminPorts[i % nonAdminPorts.Length]} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 445, 3389, 22 }.ToList() // Different from the ports in traffic
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
        var adminPorts = new[] { 445, 3389, 22 };

        // First source with lateral movement
        var targetHosts1 = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
                                  "192.168.1.14", "192.168.1.15", "192.168.1.16", "192.168.1.17" };
        for (int i = 0; i < targetHosts1.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.100",
                SrcPort = 50000,
                DstIp = targetHosts1[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND"
            });
        }

        // Second source with lateral movement
        var targetHosts2 = new[] { "192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23",
                                  "192.168.1.24", "192.168.1.25", "192.168.1.26" };
        for (int i = 0; i < targetHosts2.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.101",
                SrcPort = 50001,
                DstIp = targetHosts2[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = adminPorts.ToList()
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
        var targetHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
                                 "192.168.1.14", "192.168.1.15", "192.168.1.16", "192.168.1.17" };
        var adminPorts = new[] { 445, 3389, 22 };

        // Create 8 events but spread them over 25 minutes (no 10-minute window has 6 hosts)
        for (int i = 0; i < targetHosts.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i * 4), // 4-minute intervals = 28 minutes total
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = targetHosts[i],
                DstPort = adminPorts[i % adminPorts.Length],
                Direction = "INBOUND",
                RawLine = $"2024-01-01 12:{i*4:D2}:00 ALLOW TCP {srcIp} 50000 {targetHosts[i]} {adminPorts[i % adminPorts.Length]} INBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 6,
            LateralWindowMinutes = 10,
            AdminPorts = adminPorts.ToList()
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }
}