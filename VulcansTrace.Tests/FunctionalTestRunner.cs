using System;
using System.Linq;
using System.Text;
using System.Threading;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using Xunit;
using Xunit.Abstractions;

namespace VulcansTrace.Tests;

public class FunctionalTestRunner
{
    private readonly ITestOutputHelper _output;

    public FunctionalTestRunner(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void AnalyzeComprehensiveLogWithAllProfiles()
    {
        // Build the full analyzer stack
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
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Comprehensive synthetic test log with multiple attack patterns.
        // These fixtures use the simplified direction-after-dst-port shape rather than native pfirewall.log rows.
        var testLog = @"#Fields: date time action protocol src-ip dst-ip src-port dst-port direction
# === PORT SCAN PATTERN ===
2024-03-15 10:00:00 DROP TCP 10.0.0.50 192.168.1.100 45000 21 INBOUND
2024-03-15 10:00:01 DROP TCP 10.0.0.50 192.168.1.100 45001 22 INBOUND
2024-03-15 10:00:02 DROP TCP 10.0.0.50 192.168.1.100 45002 23 INBOUND
2024-03-15 10:00:03 DROP TCP 10.0.0.50 192.168.1.100 45003 25 INBOUND
2024-03-15 10:00:04 DROP TCP 10.0.0.50 192.168.1.100 45004 53 INBOUND
2024-03-15 10:00:05 DROP TCP 10.0.0.50 192.168.1.100 45005 80 INBOUND
2024-03-15 10:00:06 DROP TCP 10.0.0.50 192.168.1.100 45006 110 INBOUND
2024-03-15 10:00:07 DROP TCP 10.0.0.50 192.168.1.100 45007 135 INBOUND
2024-03-15 10:00:08 DROP TCP 10.0.0.50 192.168.1.100 45008 139 INBOUND
2024-03-15 10:00:09 DROP TCP 10.0.0.50 192.168.1.100 45009 443 INBOUND

# === FLOOD PATTERN ===
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50000 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50001 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50002 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50003 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50004 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50005 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50006 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50007 80 INBOUND
2024-03-15 10:05:00 ALLOW TCP 10.0.0.60 192.168.1.50 50008 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50009 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50010 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50011 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50012 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50013 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50014 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50015 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50016 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50017 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50018 80 INBOUND
2024-03-15 10:05:01 ALLOW TCP 10.0.0.60 192.168.1.50 50019 80 INBOUND

# === LATERAL MOVEMENT PATTERN ===
2024-03-15 10:10:00 ALLOW TCP 192.168.1.200 192.168.1.10 55000 445 OUTBOUND
2024-03-15 10:10:05 ALLOW TCP 192.168.1.200 192.168.1.11 55001 445 OUTBOUND
2024-03-15 10:10:10 ALLOW TCP 192.168.1.200 192.168.1.12 55002 3389 OUTBOUND
2024-03-15 10:10:15 ALLOW TCP 192.168.1.200 192.168.1.13 55003 22 OUTBOUND
2024-03-15 10:10:20 ALLOW TCP 192.168.1.200 192.168.1.14 55004 445 OUTBOUND
2024-03-15 10:10:25 ALLOW TCP 192.168.1.200 192.168.1.15 55005 3389 OUTBOUND
2024-03-15 10:10:30 ALLOW TCP 192.168.1.200 192.168.1.16 55006 22 OUTBOUND
2024-03-15 10:10:35 ALLOW TCP 192.168.1.200 192.168.1.17 55007 445 OUTBOUND
2024-03-15 10:10:40 ALLOW TCP 192.168.1.200 192.168.1.18 55008 3389 OUTBOUND
2024-03-15 10:10:45 ALLOW TCP 192.168.1.200 192.168.1.19 55009 22 OUTBOUND

# === BEACONING PATTERN ===
2024-03-15 11:00:00 ALLOW TCP 192.168.1.150 203.0.113.99 60000 443 OUTBOUND
2024-03-15 11:01:00 ALLOW TCP 192.168.1.150 203.0.113.99 60001 443 OUTBOUND
2024-03-15 11:02:00 ALLOW TCP 192.168.1.150 203.0.113.99 60002 443 OUTBOUND
2024-03-15 11:03:00 ALLOW TCP 192.168.1.150 203.0.113.99 60003 443 OUTBOUND
2024-03-15 11:04:00 ALLOW TCP 192.168.1.150 203.0.113.99 60004 443 OUTBOUND
2024-03-15 11:05:00 ALLOW TCP 192.168.1.150 203.0.113.99 60005 443 OUTBOUND
2024-03-15 11:06:00 ALLOW TCP 192.168.1.150 203.0.113.99 60006 443 OUTBOUND
2024-03-15 11:07:00 ALLOW TCP 192.168.1.150 203.0.113.99 60007 443 OUTBOUND
2024-03-15 11:08:00 ALLOW TCP 192.168.1.150 203.0.113.99 60008 443 OUTBOUND
2024-03-15 11:09:00 ALLOW TCP 192.168.1.150 203.0.113.99 60009 443 OUTBOUND

# === POLICY VIOLATION PATTERN ===
2024-03-15 12:00:00 ALLOW TCP 192.168.1.100 198.51.100.50 61000 21 OUTBOUND
2024-03-15 12:00:30 ALLOW TCP 192.168.1.101 198.51.100.51 61001 23 OUTBOUND
2024-03-15 12:01:00 ALLOW TCP 192.168.1.102 198.51.100.52 61002 445 OUTBOUND

# === NOVELTY PATTERN ===
2024-03-15 13:00:00 ALLOW TCP 192.168.1.80 8.8.8.8 62000 53 OUTBOUND
2024-03-15 13:00:10 ALLOW TCP 192.168.1.80 1.1.1.1 62001 53 OUTBOUND
2024-03-15 13:00:20 ALLOW TCP 192.168.1.80 9.9.9.9 62002 53 OUTBOUND

# Normal traffic
2024-03-15 14:00:00 ALLOW TCP 192.168.1.50 10.0.0.1 40000 443 OUTBOUND
2024-03-15 14:00:01 ALLOW TCP 192.168.1.51 10.0.0.2 40001 80 OUTBOUND
";

        var sb = new StringBuilder();
        sb.AppendLine("=" + new string('=', 79));
        sb.AppendLine(" VulcansTrace Functional Test - All Intensity Profiles");
        sb.AppendLine("=" + new string('=', 79));
        sb.AppendLine();

        foreach (var level in new[] { IntensityLevel.Low, IntensityLevel.Medium, IntensityLevel.High })
        {
            sb.AppendLine($"### {level.ToString().ToUpper()} INTENSITY ###");
            sb.AppendLine(new string('-', 40));

            var result = analyzer.Analyze(testLog, level, CancellationToken.None);

            sb.AppendLine($"Total Lines:   {result.TotalLines}");
            sb.AppendLine($"Parsed Lines:  {result.ParsedLines}");
            sb.AppendLine($"Ignored Lines: {result.IgnoredLines}");
            sb.AppendLine($"Parse Errors:  {result.ParseErrorCount}");
            sb.AppendLine($"Warnings:      {result.Warnings.Count}");
            sb.AppendLine($"Findings:      {result.Findings.Count}");
            sb.AppendLine();

            if (result.Findings.Count > 0)
            {
                sb.AppendLine("FINDINGS:");
                var grouped = result.Findings.GroupBy(f => f.Category);
                foreach (var group in grouped.OrderBy(g => g.Key))
                {
                    sb.AppendLine($"  [{group.Key}]");
                    foreach (var finding in group.OrderByDescending(f => f.Severity))
                    {
                        sb.AppendLine($"    - {finding.Severity,-10} | {finding.SourceHost,-15} -> {finding.Target}");
                        sb.AppendLine($"      {finding.ShortDescription}");
                    }
                }
            }
            else
            {
                sb.AppendLine("No findings at this intensity level.");
            }

            if (result.Warnings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("WARNINGS:");
                foreach (var warning in result.Warnings)
                {
                    sb.AppendLine($"  ! {warning}");
                }
            }

            sb.AppendLine();
            sb.AppendLine();
        }

        sb.AppendLine("=" + new string('=', 79));
        sb.AppendLine(" Test Complete");
        sb.AppendLine("=" + new string('=', 79));

        _output.WriteLine(sb.ToString());

        // Verify at least one finding was detected
        var highResult = analyzer.Analyze(testLog, IntensityLevel.High, CancellationToken.None);
        Assert.NotEmpty(highResult.Findings);
    }
}
