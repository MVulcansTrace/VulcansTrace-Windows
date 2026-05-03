using System.Globalization;
using VulcansTrace.Core;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;

namespace VulcansTrace.Tests.Engine;

public class SentryAnalyzerIntegrationTests
{
    public static IEnumerable<object[]> BeaconOffsetData()
    {
        yield return new object[] { new[] { 0, 60, 122, 180 } };
        yield return new object[] { new[] { 0, 70, 140, 210 } };
    }

    [Theory]
    [MemberData(nameof(BeaconOffsetData))]
    public void Analyze_WithCompositeSignals_EmitsFindingsAcrossDetectors(int[] beaconOffsets)
    {
        var analyzer = CreateAnalyzer();

        var beaconBase = new DateTime(2024, 3, 1, 13, 0, 0);
        var rawLog = BuildCompositeLog(beaconBase, beaconOffsets);

        var result = analyzer.Analyze(rawLog, IntensityLevel.High, CancellationToken.None);

        Assert.Equal(19, result.TotalLines);
        Assert.Equal(17, result.ParsedLines);
        Assert.Equal(2, result.IgnoredLines);
        Assert.Single(result.ParseErrors);

        Assert.Equal(new DateTime(2024, 3, 1, 12, 40, 0), result.TimeRangeStart);
        Assert.Equal(new DateTime(2024, 3, 1, 13, 30, 30), result.TimeRangeEnd);

        Assert.Equal(17, result.Entries.Count);
        Assert.Equal(5, result.Findings.Count);

        var portScan = Assert.Single(result.Findings, f => f.Category == "PortScan");
        Assert.Equal("10.0.0.10", portScan.SourceHost);
        Assert.Equal(Severity.Medium, portScan.Severity);

        var beaconing = Assert.Single(result.Findings, f => f.Category == "Beaconing");
        Assert.Equal("10.0.0.20", beaconing.SourceHost);
        Assert.Equal("203.0.113.5:443", beaconing.Target);
        Assert.Equal(Severity.Critical, beaconing.Severity);

        var lateral = Assert.Single(result.Findings, f => f.Category == "LateralMovement");
        Assert.Equal("10.0.0.20", lateral.SourceHost);
        Assert.Equal("multiple internal hosts", lateral.Target);
        Assert.Equal(Severity.Critical, lateral.Severity);

        var policy = result.Findings.Where(f => f.Category == "PolicyViolation").ToList();
        Assert.Equal(2, policy.Count);
        Assert.All(policy, f =>
        {
            Assert.Equal("10.0.0.30", f.SourceHost);
            Assert.Equal(Severity.High, f.Severity);
        });
    }

    private static SentryAnalyzer CreateAnalyzer()
    {
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };
        var riskEscalator = new RiskEscalator();

        return new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);
    }

    private static string BuildCompositeLog(DateTime beaconBase, IReadOnlyList<int> beaconOffsets)
    {
        var lines = new List<string>
        {
            "# Combined log with noise and multiple signals",
            "not-a-log-line"
        };

        var portScanBase = new DateTime(2024, 3, 1, 12, 40, 0);
        var portScanTargets = new[] { 21, 22, 23, 25, 53, 80, 110, 143 };
        for (var i = 0; i < portScanTargets.Length; i++)
        {
            var timestamp = portScanBase.AddSeconds(30 * i);
            lines.Add(FormatLine(timestamp, "ALLOW", "TCP", "10.0.0.10", 40000 + i, $"10.0.1.{i + 1}", portScanTargets[i], "OUTBOUND"));
        }

        const string beaconSrc = "10.0.0.20";
        foreach (var offset in beaconOffsets)
        {
            var timestamp = beaconBase.AddSeconds(offset);
            lines.Add(FormatLine(timestamp, "ALLOW", "TCP", beaconSrc, 51000 + offset, "203.0.113.5", 443, "OUTBOUND"));
        }

        lines.Add(FormatLine(beaconBase.AddMinutes(10), "ALLOW", "TCP", beaconSrc, 52000, "10.0.5.5", 445, "OUTBOUND"));
        lines.Add(FormatLine(beaconBase.AddMinutes(12), "ALLOW", "TCP", beaconSrc, 52001, "10.0.5.6", 3389, "OUTBOUND"));
        lines.Add(FormatLine(beaconBase.AddMinutes(14), "ALLOW", "TCP", beaconSrc, 52002, "fd00::1", 22, "OUTBOUND"));

        var policyBase = beaconBase.AddMinutes(30);
        const string policySrc = "10.0.0.30";
        lines.Add(FormatLine(policyBase, "ALLOW", "TCP", policySrc, 53000, "198.51.100.10", 445, "OUTBOUND"));
        lines.Add(FormatLine(policyBase.AddSeconds(30), "ALLOW", "TCP", policySrc, 53001, "198.51.100.10", 445, "OUTBOUND"));

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatLine(DateTime timestamp, string action, string protocol, string srcIp, int srcPort, string dstIp, int dstPort, string direction) =>
        string.Format(
            CultureInfo.InvariantCulture,
            "{0:yyyy-MM-dd HH:mm:ss} {1} {2} {3} {5} {4} {6} {7}",
            timestamp,
            action,
            protocol,
            srcIp,
            srcPort,
            dstIp,
            dstPort,
            direction);

    [Theory]
    [InlineData(IntensityLevel.Medium, 1, 0)]
    [InlineData(IntensityLevel.High, 2, 1)]
    public void Analyze_FloodAndNoveltyAcrossIntensities(IntensityLevel intensity, int expectedFindings, int expectedNovelty)
    {
        var analyzer = CreateAnalyzer();
        var rawLog = BuildFloodAndNoveltyLog();

        var result = analyzer.Analyze(rawLog, intensity, CancellationToken.None);

        Assert.Equal(203, result.TotalLines);
        Assert.Equal(201, result.ParsedLines);
        Assert.Equal(2, result.IgnoredLines);
        Assert.Single(result.ParseErrors);

        Assert.Equal(new DateTime(2024, 3, 2, 9, 0, 0), result.TimeRangeStart);
        Assert.Equal(new DateTime(2024, 3, 2, 9, 0, 55), result.TimeRangeEnd);
        Assert.Equal(201, result.Entries.Count);
        Assert.Equal(expectedFindings, result.Findings.Count);

        var flood = Assert.Single(result.Findings, f => f.Category == "Flood");
        Assert.Equal("10.1.1.10", flood.SourceHost);
        Assert.Equal("multiple hosts/ports", flood.Target);
        Assert.Equal(Severity.High, flood.Severity);

        var noveltyFindings = result.Findings.Where(f => f.Category == "Novelty").ToList();
        Assert.Equal(expectedNovelty, noveltyFindings.Count);
        if (expectedNovelty == 1)
        {
            var novelty = noveltyFindings[0];
            Assert.Equal("10.1.2.20", novelty.SourceHost);
            Assert.Equal("198.51.100.77:443", novelty.Target);
            Assert.Equal(Severity.Low, novelty.Severity);
        }
    }

    private static string BuildFloodAndNoveltyLog()
    {
        var lines = new List<string>
        {
            "# Flood and novelty scenario",
            "invalid-line"
        };

        var floodBase = new DateTime(2024, 3, 2, 9, 0, 0);
        const string floodSrc = "10.1.1.10";
        for (var i = 0; i < 200; i++)
        {
            var ts = floodBase.AddSeconds(i / 4);
            lines.Add(FormatLine(ts, "ALLOW", "TCP", floodSrc, 40000 + i, "198.51.100.10", 80, "OUTBOUND"));
        }

        var noveltyTime = floodBase.AddSeconds(55);
        lines.Add(FormatLine(noveltyTime, "ALLOW", "TCP", "10.1.2.20", 41000, "198.51.100.77", 443, "OUTBOUND"));

        return string.Join(Environment.NewLine, lines);
    }

    [Fact]
    public void Analyze_WithOverrideProfile_CollectsWarnings()
    {
        var analyzer = CreateAnalyzer();
        var rawLog = BuildCompositeLog(new DateTime(2024, 3, 1, 13, 0, 0), new[] { 0, 60, 120, 180 });

        var baseProfile = new AnalysisProfileProvider().GetProfile(IntensityLevel.High);
        var profile = baseProfile with 
        { 
            PortScanMaxEntriesPerSource = 5, 
            PortScanMinPorts = 4 
        };

        var result = analyzer.Analyze(rawLog, IntensityLevel.High, CancellationToken.None, profile);

        Assert.NotEmpty(result.Findings);
        Assert.NotEmpty(result.Warnings);
        Assert.Contains("truncated", result.Warnings.First(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_PortScanTruncation_DoesNotAffectEligibilityCheck()
    {
        var detector = new PortScanDetector();
        var baseTime = new DateTime(2024, 3, 1, 12, 0, 0);

        // 10 entries: first 5 all target port 80, next 5 each target a different port.
        // Full set has 6 distinct ports (80, 21, 22, 23, 25, 53).
        var entries = new List<LogEntry>();
        for (int i = 0; i < 5; i++)
        {
            entries.Add(new LogEntry
            {
                Timestamp = baseTime.AddSeconds(i),
                Action = "DROP",
                Protocol = "TCP",
                SrcIp = "10.0.0.50",
                DstIp = "192.168.1.100",
                SrcPort = 45000 + i,
                DstPort = 80
            });
        }
        entries.Add(new LogEntry { Timestamp = baseTime.AddSeconds(5), Action = "DROP", Protocol = "TCP", SrcIp = "10.0.0.50", DstIp = "192.168.1.100", SrcPort = 45005, DstPort = 21 });
        entries.Add(new LogEntry { Timestamp = baseTime.AddSeconds(6), Action = "DROP", Protocol = "TCP", SrcIp = "10.0.0.50", DstIp = "192.168.1.100", SrcPort = 45006, DstPort = 22 });
        entries.Add(new LogEntry { Timestamp = baseTime.AddSeconds(7), Action = "DROP", Protocol = "TCP", SrcIp = "10.0.0.50", DstIp = "192.168.1.100", SrcPort = 45007, DstPort = 23 });
        entries.Add(new LogEntry { Timestamp = baseTime.AddSeconds(8), Action = "DROP", Protocol = "TCP", SrcIp = "10.0.0.50", DstIp = "192.168.1.100", SrcPort = 45008, DstPort = 25 });
        entries.Add(new LogEntry { Timestamp = baseTime.AddSeconds(9), Action = "DROP", Protocol = "TCP", SrcIp = "10.0.0.50", DstIp = "192.168.1.100", SrcPort = 45009, DstPort = 53 });

        // Without truncation: 6 distinct ports ≥ 4 → port scan detected
        var noCapProfile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 4,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = null
        };
        var noCapFindings = detector.Detect(entries, noCapProfile, CancellationToken.None).ToList();
        Assert.Single(noCapFindings);
        Assert.Equal("PortScan", noCapFindings[0].Category);

        // With truncation to 5 entries: truncated subset has only 1 distinct port (80),
        // so no finding is produced from the truncated data. However, the detector must NOT
        // skip the source at the eligibility stage (which was the bug). Instead, it should
        // proceed to truncate, emit a warning, and then analyze the truncated data.
        var capProfile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 4,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = 5
        };
        var capFindings = detector.Detect(entries, capProfile, CancellationToken.None).ToList();
        Assert.Empty(capFindings); // truncated subset doesn't meet per-window threshold
        Assert.Single(detector.Warnings); // but truncation warning proves it didn't skip early
        Assert.Contains("truncated", detector.Warnings[0], StringComparison.OrdinalIgnoreCase);
    }
}
