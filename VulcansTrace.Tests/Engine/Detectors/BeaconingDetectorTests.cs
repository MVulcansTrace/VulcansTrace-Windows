using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Detectors;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine.Detectors;

public class BeaconingDetectorTests
{
    private readonly BeaconingDetector _detector = new();

    [Fact]
    public void Detect_WithRegularBeaconing_ReturnsFinding()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var dstIp = "203.0.113.50";
        var dstPort = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // Create 10 events with 90-second intervals (very regular, std dev will be ~0)
        for (int i = 0; i < 10; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 90),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = dstIp,
                DstPort = dstPort,
                Direction = "OUTBOUND",
                RawLine = $"2024-01-01 12:{i * 90 / 60:D2}:{(i * 90) % 60:D2} ALLOW TCP {srcIp} 50000 {dstIp} {dstPort} OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 60,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("Beaconing", findings[0].Category);
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Equal(srcIp, findings[0].SourceHost);
        Assert.Equal($"{dstIp}:{dstPort}", findings[0].Target);
        Assert.Contains("Regular beaconing", findings[0].ShortDescription);
        Assert.Contains("90.0s", findings[0].Details); // Mean should be ~90 seconds
        Assert.Contains("10 events", findings[0].Details);
    }

    [Fact]
    public void Detect_WithIrregularIntervals_ReturnsNoFindings()
    {
        // Arrange - Create events with very irregular timing (high standard deviation)
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var dstIp = "203.0.113.50";
        var dstPort = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // Intervals: 30s, 180s, 45s, 300s, 60s, 240s (very irregular)
        var intervals = new[] { 30, 180, 45, 300, 60, 240, 90, 150, 120 };
        var currentTime = baseTime;

        for (int i = 0; i < intervals.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = currentTime,
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = dstIp,
                DstPort = dstPort,
                Direction = "OUTBOUND"
            });
            currentTime = currentTime.AddSeconds(intervals[i]);
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0, // Low threshold - regular beacons must have very low std dev
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithBeaconingDisabled_ReturnsNoFindings()
    {
        // Arrange
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var dstIp = "203.0.113.50";
        var dstPort = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // Create regular pattern that would normally trigger detection
        for (int i = 0; i < 10; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 60), // 60-second intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = dstIp,
                DstPort = dstPort,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = false, // Disabled
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
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
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithInsufficientEvents_ReturnsNoFindings()
    {
        // Arrange - Only 5 events, but threshold is 8
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var dstIp = "203.0.113.50";
        var dstPort = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        for (int i = 0; i < 5; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 60), // Regular 60-second intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = dstIp,
                DstPort = dstPort,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8, // Higher than number of events
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithMeanIntervalBelowThreshold_ReturnsNoFindings()
    {
        // Arrange - Mean interval is 20 seconds, but minimum threshold is 60 seconds
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var dstIp = "203.0.113.50";
        var dstPort = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        for (int i = 0; i < 10; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 20), // 20-second intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = dstIp,
                DstPort = dstPort,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 60, // Higher than our interval
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithMeanIntervalAboveThreshold_ReturnsNoFindings()
    {
        // Arrange - Mean interval is 1200 seconds (20 minutes), but maximum threshold is 900 seconds
        var entries = new List<LogEntry>();
        var srcIp = "192.168.1.100";
        var dstIp = "203.0.113.50";
        var dstPort = 443;
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        for (int i = 0; i < 8; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i * 20), // 20-minute intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = srcIp,
                SrcPort = 50000,
                DstIp = dstIp,
                DstPort = dstPort,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900, // Lower than our interval
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_WithMultipleBeaconingSources_ReturnsMultipleFindings()
    {
        // Arrange - Two different sources both beaconing to different destinations
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // First source beaconing
        for (int i = 0; i < 8; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 120), // 120-second intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.100",
                SrcPort = 50000,
                DstIp = "203.0.113.50",
                DstPort = 443,
                Direction = "OUTBOUND"
            });
        }

        // Second source beaconing
        for (int i = 0; i < 8; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 180), // 180-second intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.101",
                SrcPort = 50001,
                DstIp = "203.0.113.60",
                DstPort = 8443,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 60,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.100" && f.Target == "203.0.113.50:443");
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.101" && f.Target == "203.0.113.60:8443");
    }

    [Fact]
    public void Detect_WithMixedTraffic_ReturnsOnlyBeaconingFindings()
    {
        // Arrange - Mix of regular beaconing and other irregular traffic
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

        // Regular beaconing pattern (should trigger)
        for (int i = 0; i < 10; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddMinutes(i), // 1-minute intervals
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.100",
                SrcPort = 50000,
                DstIp = "203.0.113.50",
                DstPort = 443,
                Direction = "OUTBOUND"
            });
        }

        // Irregular traffic (should not trigger)
        var irregularTimes = new[] { 90, 300, 60, 600, 45, 180 };
        var currentTime = baseTime.AddHours(1);
        for (int i = 0; i < irregularTimes.Length; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = currentTime,
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "192.168.1.101",
                SrcPort = 50001,
                DstIp = "203.0.113.60",
                DstPort = 8080,
                Direction = "OUTBOUND"
            });
            currentTime = currentTime.AddSeconds(irregularTimes[i]);
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 8,
            BeaconStdDevThreshold = 5.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Equal("203.0.113.50:443", findings[0].Target);
    }

    [Fact]
    public void Detect_WithOutlierTrimStillFlagsBeacon()
    {
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 5, 1, 0, 0, 0);
        // Regular 60s beacons with two outliers at 5s and 300s
        var offsets = new[] { 0, 60, 120, 180, 240, 300, 305, 360, 420, 480 };
        foreach (var offset in offsets)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(offset),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "10.0.0.5",
                SrcPort = 50000 + offset,
                DstIp = "203.0.113.5",
                DstPort = 8080,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 6,
            BeaconStdDevThreshold = 8.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 300,
            BeaconTrimPercent = 0.2
        };

        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

        Assert.Single(findings);
        Assert.Equal("Beaconing", findings[0].Category);
    }

    [Fact]
    public void Detect_WithNoisyPeriodicTraffic_DoesNotTriggerAtMedium()
    {
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 5, 1, 0, 0, 0);
        // Periodic-ish with jitter that should be filtered out after trim/stddev
        var offsets = new[] { 0, 45, 110, 170, 250, 330, 405, 490 };
        foreach (var offset in offsets)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(offset),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "10.0.0.6",
                SrcPort = 60000 + offset,
                DstIp = "203.0.113.6",
                DstPort = 8443,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 6,
            BeaconStdDevThreshold = 3.0,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 200,
            BeaconMinDurationSeconds = 200,
            BeaconTrimPercent = 0.1
        };

        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_RespectsSampleCap()
    {
        var entries = new List<LogEntry>();
        var baseTime = new DateTime(2024, 5, 1, 0, 0, 0);
        for (int i = 0; i < 300; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i * 60),
                Action = "ALLOW",
                Protocol = "TCP",
                SrcIp = "10.0.0.7",
                SrcPort = 61000 + i,
                DstIp = "203.0.113.7",
                DstPort = 9000,
                Direction = "OUTBOUND"
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 4,
            BeaconStdDevThreshold = 8.0,
            BeaconMinIntervalSeconds = 10,
            BeaconMaxIntervalSeconds = 900,
            BeaconMaxSamplesPerTuple = 50,
            BeaconMinDurationSeconds = 120,
            BeaconTrimPercent = 0.1
        };

        var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();
        Assert.Single(findings);
    }
}
