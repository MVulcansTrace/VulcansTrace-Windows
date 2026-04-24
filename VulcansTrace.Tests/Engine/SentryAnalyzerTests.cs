using VulcansTrace.Core;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using Xunit;

namespace VulcansTrace.Tests.Engine;

public class SentryAnalyzerTests
{
    [Fact]
    public void Analyze_WithEmptyLog_ReturnsEmptyResult()
    {
        // Arrange
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new List<IDetector>();
        var riskEscalator = new RiskEscalator();

        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Act
        var result = analyzer.Analyze("", IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Equal(0, result.TotalLines);
        Assert.Equal(0, result.ParsedLines);
        Assert.Equal(0, result.IgnoredLines);
        Assert.Empty(result.Entries);
        Assert.Empty(result.Findings);
        Assert.Null(result.TimeRangeStart);
        Assert.Null(result.TimeRangeEnd);
    }

    [Fact]
    public void Analyze_WithValidLog_ParsesEntriesCorrectly()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = @"# Version: 1.5
# Software: Windows Firewall
# Time Format: Local
2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 203.0.113.50 50000 443 OUTBOUND
2024-01-01 12:01:00 ALLOW TCP 192.168.1.100 203.0.113.60 50001 80 OUTBOUND";

        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new List<IDetector>();
        var riskEscalator = new RiskEscalator();

        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Act
        var result = analyzer.Analyze(rawLog, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Equal(5, result.TotalLines); // 3 comment lines + 2 data lines
        Assert.Equal(2, result.ParsedLines);
        Assert.Equal(3, result.IgnoredLines);
        Assert.Equal(2, result.Entries.Count);
        Assert.NotNull(result.TimeRangeStart);
        Assert.NotNull(result.TimeRangeEnd);
        Assert.Equal(new DateTime(2024, 1, 1, 12, 0, 0), result.TimeRangeStart.Value);
        Assert.Equal(new DateTime(2024, 1, 1, 12, 1, 0), result.TimeRangeEnd.Value);
    }

    [Fact]
    public void Analyze_WithFakeDetector_FiltersByMinSeverity()
    {
        // Arrange - simplified fixture format
        var rawLog = "2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 203.0.113.50 50000 443 OUTBOUND";

        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var riskEscalator = new RiskEscalator();

        // Fake detector that returns specific findings
        var fakeDetector = new FakeDetector();
        var detectors = new List<IDetector> { fakeDetector };

        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Act - Low intensity should filter out Low severity findings
        var resultLow = analyzer.Analyze(rawLog, IntensityLevel.Low, CancellationToken.None);
        // Act - Medium intensity should include Medium severity findings
        var resultMedium = analyzer.Analyze(rawLog, IntensityLevel.Medium, CancellationToken.None);
        // Act - High intensity should include all findings
        var resultHigh = analyzer.Analyze(rawLog, IntensityLevel.High, CancellationToken.None);

        // Assert
        // Low intensity (MinSeverityToShow = High) - only High and Critical findings
        Assert.Equal(2, resultLow.Findings.Count); // High and Critical
        Assert.All(resultLow.Findings, f => Assert.True(f.Severity >= Severity.High));

        // Medium intensity (MinSeverityToShow = Medium) - Medium, High, and Critical findings
        Assert.Equal(3, resultMedium.Findings.Count); // Medium, High, and Critical
        Assert.All(resultMedium.Findings, f => Assert.True(f.Severity >= Severity.Medium));

        // High intensity (MinSeverityToShow = Info) - all findings
        Assert.Equal(4, resultHigh.Findings.Count); // Info, Medium, High, and Critical
        Assert.All(resultHigh.Findings, f => Assert.True(f.Severity >= Severity.Info));
    }

    [Fact]
    public void Analyze_WithMultipleDetectors_CombinesAllFindings()
    {
        // Arrange - simplified fixture format
        var rawLog = @"2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 203.0.113.50 50000 443 OUTBOUND
2024-01-01 12:01:00 ALLOW TCP 192.168.1.101 192.168.1.10 50001 22 OUTBOUND";

        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var riskEscalator = new RiskEscalator();

        // Two fake detectors that return different findings
        var detector1 = new FakeDetector("Detector1");
        var detector2 = new FakeDetector("Detector2");
        var detectors = new List<IDetector> { detector1, detector2 };

        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Act
        var result = analyzer.Analyze(rawLog, IntensityLevel.High, CancellationToken.None); // High intensity shows all

        // Assert
        // Should have 8 findings total (4 from each detector)
        Assert.Equal(8, result.Findings.Count);

        // Should have findings from both detectors
        var detector1Findings = result.Findings.Where(f => f.Category.Contains("Detector1")).ToList();
        var detector2Findings = result.Findings.Where(f => f.Category.Contains("Detector2")).ToList();

        Assert.Equal(4, detector1Findings.Count);
        Assert.Equal(4, detector2Findings.Count);
    }

    [Fact]
    public void Analyze_WithRiskEscalation_AppliesEscalationCorrectly()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = @"2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 203.0.113.50 50000 443 OUTBOUND
2024-01-01 12:01:00 ALLOW TCP 192.168.1.100 192.168.1.10 50001 22 OUTBOUND";

        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var riskEscalator = new RiskEscalator();

        // Fake detector that returns Beaconing and LateralMovement findings for same host
        var escalationDetector = new EscalationTestDetector();
        var detectors = new List<IDetector> { escalationDetector };

        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Act
        var result = analyzer.Analyze(rawLog, IntensityLevel.High, CancellationToken.None);

        // Assert
        // Should have findings that were escalated to Critical
        var criticalFindings = result.Findings.Where(f => f.Severity == Severity.Critical).ToList();
        Assert.NotEmpty(criticalFindings);

        // All findings should be from the same source host and escalated to Critical
        Assert.All(criticalFindings, f => Assert.Equal("192.168.1.100", f.SourceHost));
    }

    [Fact]
    public void AnalyseConstructor_WithNullParameters_ThrowsArgumentNullException()
    {
        // Arrange
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new List<IDetector>();
        var riskEscalator = new RiskEscalator();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new SentryAnalyzer(null!, profileProvider, detectors, riskEscalator));
        Assert.Throws<ArgumentNullException>(() =>
            new SentryAnalyzer(parser, null!, detectors, riskEscalator));
        Assert.Throws<ArgumentNullException>(() =>
            new SentryAnalyzer(parser, profileProvider, null!, riskEscalator));
        Assert.Throws<ArgumentNullException>(() =>
            new SentryAnalyzer(parser, profileProvider, detectors, null!));
    }

    // Fake detector for testing
    private class FakeDetector : IDetector
    {
        private readonly string _prefix;

        public FakeDetector(string prefix = "Test")
        {
            _prefix = prefix;
        }

        public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
        {
            if (entries.Count == 0)
                yield break;

            var sourceHost = entries[0].SrcIp;

            yield return new Finding
            {
                Category = $"{_prefix} Info",
                Severity = Severity.Info,
                SourceHost = sourceHost,
                Target = "test:80",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Test info finding",
                Details = "Test details"
            };

            yield return new Finding
            {
                Category = $"{_prefix} Medium",
                Severity = Severity.Medium,
                SourceHost = sourceHost,
                Target = "test:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Test medium finding",
                Details = "Test details"
            };

            yield return new Finding
            {
                Category = $"{_prefix} High",
                Severity = Severity.High,
                SourceHost = sourceHost,
                Target = "test:8080",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Test high finding",
                Details = "Test details"
            };

            yield return new Finding
            {
                Category = $"{_prefix} Critical",
                Severity = Severity.Critical,
                SourceHost = sourceHost,
                Target = "test:9000",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Test critical finding",
                Details = "Test details"
            };
        }
    }

    // Special detector for testing risk escalation
    private class EscalationTestDetector : IDetector
    {
        public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
        {
            if (entries.Count == 0)
                yield break;

            var sourceHost = entries[0].SrcIp;

            // Return Beaconing and LateralMovement findings for same host
            // These should be escalated to Critical by RiskEscalator
            yield return new Finding
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = sourceHost,
                Target = "external:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Test beaconing",
                Details = "Test beaconing details"
            };

            yield return new Finding
            {
                Category = "LateralMovement",
                Severity = Severity.High,
                SourceHost = sourceHost,
                Target = "internal:22",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Test lateral movement",
                Details = "Test lateral movement details"
            };
        }
    }

    [Fact]
    public void Analyze_WithManyParseErrors_CapsStoredErrorsButKeepsTotalCount()
    {
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new List<IDetector>();
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < 750; i++)
        {
            sb.AppendLine("INVALID");
        }

        var result = analyzer.Analyze(sb.ToString(), IntensityLevel.Low, CancellationToken.None);

        Assert.Equal(750, result.ParseErrorCount);
        Assert.Equal(500, result.ParseErrors.Count); // capped in analyzer
        Assert.True(result.ParseErrors.Count > 0);
    }
}
