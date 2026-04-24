using VulcansTrace.Core;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using System.Text;
using System.Threading;
using Xunit;

namespace VulcansTrace.Tests.Engine;

public class SentryAnalyzerRobustnessTests
{
    private class CrashingDetector : IDetector
    {
        public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken token)
        {
            throw new InvalidOperationException("Detector crashed!");
        }
    }

    private class WorkingDetector : IDetector
    {
        public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken token)
        {
            return new[]
            {
                new Finding
                {
                    Category = "Working",
                    Severity = Severity.High,
                    ShortDescription = "Working detector found something"
                }
            };
        }
    }

    [Fact]
    public void Analyze_WhenOneDetectorCrashes_ShouldContinueAndReportWarning()
    {
        // Arrange
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var riskEscalator = new RiskEscalator();
        
        var detectors = new IDetector[]
        {
            new CrashingDetector(),
            new WorkingDetector()
        };

        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);
        // Simplified fixture format with direction immediately after dst-port
        var rawLog = "2024-01-01 12:00:00 ALLOW TCP 192.168.1.1 10.0.0.1 80 12345 INBOUND";

        // Act
        var result = analyzer.Analyze(rawLog, IntensityLevel.Low, CancellationToken.None);

        // Assert
        // 1. Should have findings from the working detector
        Assert.Contains(result.Findings, f => f.Category == "Working");

        // 2. Should have a warning about the crashed detector
        Assert.Contains(result.Warnings, w => w.Contains("Detector crashed") && w.Contains("CrashingDetector"));
    }

    [Fact]
    public void Analyze_WithHighVolumeValidLog_CompletesAndTracksCounts()
    {
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, Array.Empty<IDetector>(), riskEscalator);

        var sb = new StringBuilder();
        for (var i = 0; i < 5000; i++)
        {
            var timestamp = new DateTime(2024, 1, 1, 0, 0, 0).AddSeconds(i);
            // Simplified fixture format with direction immediately after dst-port
            sb.AppendLine($"{timestamp:yyyy-MM-dd HH:mm:ss} ALLOW TCP 10.0.0.1 8.8.8.8 1000 53 OUTBOUND");
        }

        var log = sb.ToString().TrimEnd('\r', '\n');

        var result = analyzer.Analyze(log, IntensityLevel.Low, CancellationToken.None);

        Assert.Equal(5000, result.TotalLines);
        Assert.Equal(5000, result.ParsedLines);
        Assert.Empty(result.ParseErrors);
        Assert.Equal(new DateTime(2024, 1, 1, 0, 0, 0), result.TimeRangeStart);
        Assert.Equal(new DateTime(2024, 1, 1, 1, 23, 19), result.TimeRangeEnd);
    }

    [Fact]
    public void Analyze_WhenCancelledBeforeParsing_ThrowsOperationCanceled()
    {
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, Array.Empty<IDetector>(), riskEscalator);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            // Simplified fixture format with direction immediately after dst-port
            analyzer.Analyze("2024-01-01 00:00:00 ALLOW TCP 1.1.1.1 2.2.2.2 1 2 OUTBOUND", IntensityLevel.Low, cts.Token));
    }
}
