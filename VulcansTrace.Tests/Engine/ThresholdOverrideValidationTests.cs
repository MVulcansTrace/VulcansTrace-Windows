using System;
using System.Linq;
using System.Threading;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using Xunit;

namespace VulcansTrace.Tests.Engine;

/// <summary>
/// Validates that individual threshold overrides actually change detection output.
/// These tests prove the overrides are real features, not UI wishful thinking.
/// </summary>
public class ThresholdOverrideValidationTests
{
    private static SentryAnalyzer CreateAnalyzer()
    {
        var parser = new WindowsFirewallLogParser();
        var provider = new AnalysisProfileProvider();
        var detectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };
        var escalator = new RiskEscalator();
        return new SentryAnalyzer(parser, provider, detectors, escalator);
    }

    [Fact]
    public void PortScanMinPorts_Override_CatchesScanThatDefaultMisses()
    {
        var analyzer = CreateAnalyzer();
        var baseTime = new DateTime(2024, 3, 1, 12, 0, 0);

        // 5 distinct ports from 10.0.0.50 — NOT enough for Medium profile (needs 15)
        var lines = Enumerable.Range(0, 5)
            .Select(i => $"{baseTime.AddSeconds(i):yyyy-MM-dd HH:mm:ss} DROP TCP 10.0.0.50 192.168.1.100 {45000 + i} {21 + i} INBOUND")
            .ToList();
        var rawLog = string.Join(Environment.NewLine, lines);

        // Default Medium profile → no port scan (needs 15)
        var defaultResult = analyzer.Analyze(rawLog, IntensityLevel.Medium, CancellationToken.None);
        Assert.DoesNotContain(defaultResult.Findings, f => f.Category == "PortScan");

        // Override PortScanMinPorts to 3 → SHOULD catch the scan
        var medium = new AnalysisProfileProvider().GetProfile(IntensityLevel.Medium);
        var overridden = medium with { PortScanMinPorts = 3 };
        var overrideResult = analyzer.Analyze(rawLog, IntensityLevel.Medium, CancellationToken.None, overridden);

        Assert.Contains(overrideResult.Findings, f => f.Category == "PortScan");
    }

    [Fact]
    public void FloodMinEvents_Override_CatchesFloodThatDefaultMisses()
    {
        var analyzer = CreateAnalyzer();
        var baseTime = new DateTime(2024, 3, 1, 12, 0, 0);

        // 50 events from 10.0.0.50 in 30 seconds — NOT enough for Medium profile (needs 200)
        var lines = Enumerable.Range(0, 50)
            .Select(i => $"{baseTime.AddSeconds(i):yyyy-MM-dd HH:mm:ss} DROP TCP 10.0.0.50 192.168.1.100 {45000 + i} 80 INBOUND")
            .ToList();
        var rawLog = string.Join(Environment.NewLine, lines);

        // Default Medium profile → no flood (needs 200)
        var defaultResult = analyzer.Analyze(rawLog, IntensityLevel.Medium, CancellationToken.None);
        Assert.DoesNotContain(defaultResult.Findings, f => f.Category == "Flood");

        // Override FloodMinEvents to 40 → SHOULD catch the flood
        var medium = new AnalysisProfileProvider().GetProfile(IntensityLevel.Medium);
        var overridden = medium with { FloodMinEvents = 40 };
        var overrideResult = analyzer.Analyze(rawLog, IntensityLevel.Medium, CancellationToken.None, overridden);

        Assert.Contains(overrideResult.Findings, f => f.Category == "Flood");
    }
}
