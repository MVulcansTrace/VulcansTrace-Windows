using System.Text;
using VulcansTrace.Core;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using Xunit;
using Xunit.Abstractions;

namespace VulcansTrace.Tests.Engine;

/// <summary>
/// Validates that Low, Medium, and High intensity profiles produce genuinely different
/// findings when each attack behavior originates from a distinct source IP.
/// </summary>
/// <remarks>
/// By isolating each behavior to its own attacker, the RiskEscalator never fires
/// (no host has both Beaconing and LateralMovement), so we see the raw profile
/// thresholds and severity filtering in action.
/// </remarks>
public class IntensityComparisonTests
{
    private readonly ITestOutputHelper _output;

    public IntensityComparisonTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Theory]
    [InlineData(IntensityLevel.Low, 1, new[] { "PolicyViolation" })]
    [InlineData(IntensityLevel.Medium, 4, new[] { "PortScan", "Beaconing", "LateralMovement", "PolicyViolation" })]
    [InlineData(IntensityLevel.High, 7, new[] { "PortScan", "Beaconing", "LateralMovement", "Flood", "PolicyViolation", "Novelty" })]
    public void Analyze_IsolatedAttackers_ProducesProfileSpecificFindings(
        IntensityLevel level,
        int expectedFindingCount,
        string[] expectedCategories)
    {
        // Arrange
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        // Act
        var result = analyzer.Analyze(testLog, level, CancellationToken.None);

        // Diagnostic output
        _output.WriteLine($"=== {level} INTENSITY ===");
        _output.WriteLine($"Findings: {result.Findings.Count}");
        foreach (var f in result.Findings.OrderBy(x => x.Category))
        {
            _output.WriteLine($"  [{f.Category}] {f.Severity} from {f.SourceHost}");
        }

        // Assert — exact count
        Assert.Equal(expectedFindingCount, result.Findings.Count);

        // Assert — categories match (no extras, no missing)
        var actualCategories = result.Findings.Select(f => f.Category).Distinct().Order().ToList();
        var expectedSorted = expectedCategories.Order().ToList();
        Assert.Equal(expectedSorted, actualCategories);

        // Assert — RiskEscalator did NOT fire (no Critical findings because no host has both Beaconing + LateralMovement)
        Assert.DoesNotContain(result.Findings, f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_IsolatedAttackers_PortScan_MediumOnly()
    {
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        var low = analyzer.Analyze(testLog, IntensityLevel.Low, CancellationToken.None);
        var medium = analyzer.Analyze(testLog, IntensityLevel.Medium, CancellationToken.None);
        var high = analyzer.Analyze(testLog, IntensityLevel.High, CancellationToken.None);

        // Port scan (20 distinct ports) misses Low (threshold 30), catches Medium/High
        Assert.DoesNotContain(low.Findings, f => f.Category == "PortScan");
        Assert.Contains(medium.Findings, f => f.Category == "PortScan");
        Assert.Contains(high.Findings, f => f.Category == "PortScan");
    }

    [Fact]
    public void Analyze_IsolatedAttackers_Beaconing_MediumOnly()
    {
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        var low = analyzer.Analyze(testLog, IntensityLevel.Low, CancellationToken.None);
        var medium = analyzer.Analyze(testLog, IntensityLevel.Medium, CancellationToken.None);
        var high = analyzer.Analyze(testLog, IntensityLevel.High, CancellationToken.None);

        // Beaconing (6 events) misses Low (threshold 8), catches Medium/High
        Assert.DoesNotContain(low.Findings, f => f.Category == "Beaconing");
        Assert.Contains(medium.Findings, f => f.Category == "Beaconing");
        Assert.Contains(high.Findings, f => f.Category == "Beaconing");
    }

    [Fact]
    public void Analyze_IsolatedAttackers_LateralMovement_MediumAndHigh()
    {
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        var low = analyzer.Analyze(testLog, IntensityLevel.Low, CancellationToken.None);
        var medium = analyzer.Analyze(testLog, IntensityLevel.Medium, CancellationToken.None);
        var high = analyzer.Analyze(testLog, IntensityLevel.High, CancellationToken.None);

        // Lateral movement (5 hosts) misses Low (threshold 6), catches Medium/High
        Assert.DoesNotContain(low.Findings, f => f.Category == "LateralMovement");
        Assert.Contains(medium.Findings, f => f.Category == "LateralMovement");
        Assert.Contains(high.Findings, f => f.Category == "LateralMovement");
    }

    [Fact]
    public void Analyze_IsolatedAttackers_Flood_HighOnly()
    {
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        var low = analyzer.Analyze(testLog, IntensityLevel.Low, CancellationToken.None);
        var medium = analyzer.Analyze(testLog, IntensityLevel.Medium, CancellationToken.None);
        var high = analyzer.Analyze(testLog, IntensityLevel.High, CancellationToken.None);

        // Flood (110 events) misses Low (400) and Medium (200), catches High (100)
        Assert.DoesNotContain(low.Findings, f => f.Category == "Flood");
        Assert.DoesNotContain(medium.Findings, f => f.Category == "Flood");
        Assert.Contains(high.Findings, f => f.Category == "Flood");
    }

    [Fact]
    public void Analyze_IsolatedAttackers_Novelty_HighOnly()
    {
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        var low = analyzer.Analyze(testLog, IntensityLevel.Low, CancellationToken.None);
        var medium = analyzer.Analyze(testLog, IntensityLevel.Medium, CancellationToken.None);
        var high = analyzer.Analyze(testLog, IntensityLevel.High, CancellationToken.None);

        // Novelty disabled at Low, enabled at Medium/High
        Assert.DoesNotContain(low.Findings, f => f.Category == "Novelty");

        // At Medium: Novelty finding is Low severity, filtered by MinSeverityToShow=Medium
        Assert.DoesNotContain(medium.Findings, f => f.Category == "Novelty");

        // At High: Novelty finding is Low severity, visible because MinSeverityToShow=Info
        Assert.Contains(high.Findings, f => f.Category == "Novelty");
    }

    [Fact]
    public void Analyze_IsolatedAttackers_PolicyViolation_AllProfiles()
    {
        var testLog = BuildIsolatedAttackerLog();
        var analyzer = CreateAnalyzer();

        foreach (var level in new[] { IntensityLevel.Low, IntensityLevel.Medium, IntensityLevel.High })
        {
            var result = analyzer.Analyze(testLog, level, CancellationToken.None);
            Assert.Contains(result.Findings, f => f.Category == "PolicyViolation");
        }
    }

    /// <summary>
    /// Builds a synthetic firewall log where each attack pattern comes from a unique source IP.
    /// This prevents RiskEscalator from firing, isolating profile threshold behavior.
    /// </summary>
    private static string BuildIsolatedAttackerLog()
    {
        var sb = new StringBuilder();
        sb.AppendLine("#Fields: date time action protocol src-ip dst-ip src-port dst-port direction");

        // === PORT SCAN ===
        // 20 distinct dst ports from 10.0.0.10 → catches Medium (≥15) and High (≥8), misses Low (≥30)
        int[] scanPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080, 8443, 9000, 9090, 9200, 9300, 9400, 9500];
        for (int i = 0; i < scanPorts.Length; i++)
        {
            sb.AppendLine($"2024-03-15 10:00:{i:D2} DROP TCP 10.0.0.10 192.168.1.100 {45000 + i} {scanPorts[i]} INBOUND");
        }

        // === BEACONING ===
        // 6 events at 60-second intervals from 192.168.1.20 → catches Medium (≥6) and High (≥4), misses Low (≥8)
        for (int i = 0; i < 6; i++)
        {
            var ts = new DateTime(2024, 3, 15, 11, i, 0);
            sb.AppendLine($"{ts:yyyy-MM-dd HH:mm:ss} ALLOW TCP 192.168.1.20 203.0.113.50 {60000 + i} 443 OUTBOUND");
        }

        // === LATERAL MOVEMENT ===
        // 5 internal hosts on admin ports from 192.168.1.200 → catches Medium (≥4) and High (≥3), misses Low (≥6)
        string[] lateralHosts = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"];
        int[] lateralPorts = [445, 3389, 22, 445, 3389];
        for (int i = 0; i < lateralHosts.Length; i++)
        {
            var ts = new DateTime(2024, 3, 15, 10, 10 + i, 0);
            sb.AppendLine($"{ts:yyyy-MM-dd HH:mm:ss} ALLOW TCP 192.168.1.200 {lateralHosts[i]} {55000 + i} {lateralPorts[i]} OUTBOUND");
        }

        // === FLOOD ===
        // 110 events within 1 second from 10.0.0.40 → catches High (≥100), misses Medium (≥200) and Low (≥400)
        for (int i = 0; i < 110; i++)
        {
            sb.AppendLine($"2024-03-15 10:05:00 ALLOW TCP 10.0.0.40 192.168.1.50 {50000 + i} 80 INBOUND");
        }

        // === POLICY VIOLATION ===
        // Disallowed outbound port 21 from 192.168.1.100 → caught at all levels (High severity)
        sb.AppendLine("2024-03-15 12:00:00 ALLOW TCP 192.168.1.100 198.51.100.50 61000 21 OUTBOUND");

        // === NOVELTY ===
        // Single unique external connection from 192.168.1.80 → visible at High (Info), hidden at Medium (Low < Medium), disabled at Low
        sb.AppendLine("2024-03-15 13:00:00 ALLOW TCP 192.168.1.80 8.8.8.8 62000 53 OUTBOUND");

        return sb.ToString();
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
}
