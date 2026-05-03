using VulcansTrace.Core;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Detects port scanning activity by identifying hosts probing multiple destination ports.
/// </summary>
/// <remarks>
/// A port scan is identified when a single source IP contacts many distinct destination 
/// IP:port combinations within a configurable time window. This behavior often indicates 
/// reconnaissance activity by an attacker mapping network services.
/// <para>
/// <strong>Limitations:</strong> This detector counts distinct (DstIp, DstPort) tuples but does not
/// classify enumeration types (e.g., subnet sweeps vs. port scans). Findings use a generic
/// Target value ("multiple hosts/ports") rather than reporting specific IP ranges. For detailed
/// target analysis, reference the raw firewall logs in the evidence package.
/// </para>
/// <para>
/// Maps to MITRE ATT&CK T1046 (Network Service Discovery) as a behavioral indicator only.
/// </para>
/// </remarks>
public sealed class PortScanDetector : IDetector, IProducesWarnings
{
    private readonly List<string> _warnings = new();
    public IReadOnlyList<string> Warnings => _warnings;

    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        _warnings.Clear();

        if (!profile.EnablePortScan || entries.Count == 0)
            return Enumerable.Empty<Finding>();

        if (profile.PortScanWindowMinutes <= 0)
            throw new ArgumentOutOfRangeException(nameof(profile.PortScanWindowMinutes), "Must be greater than zero.");

        var findings = new List<Finding>();

        var bySrc = entries
            .Where(e => e.DstPort.HasValue)
            .GroupBy(e => e.SrcIp);
        foreach (var srcGroup in bySrc)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var srcIp = srcGroup.Key;

            var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
            var totalForSource = ordered.Count;

            var distinctTargetsForSource = ordered
                .Select(e => (e.DstIp, e.DstPort))
                .Distinct()
                .Count();

            if (distinctTargetsForSource < profile.PortScanMinPorts)
                continue;

            var maxEntries = profile.PortScanMaxEntriesPerSource.GetValueOrDefault();
            if (maxEntries > 0 && ordered.Count > maxEntries)
            {
                ordered = ordered.Take(maxEntries).ToList();
                _warnings.Add($"Port scan analysis for {srcIp} truncated to {maxEntries} events out of {totalForSource}.");
            }

            var byWindow = ordered.GroupBy(e =>
                new DateTime(
                    e.Timestamp.Year,
                    e.Timestamp.Month,
                    e.Timestamp.Day,
                    e.Timestamp.Hour,
                    (e.Timestamp.Minute / profile.PortScanWindowMinutes) * profile.PortScanWindowMinutes,
                    0,
                    e.Timestamp.Kind));

            foreach (var windowGroup in byWindow)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var distinctTargets = windowGroup
                    .Select(e => (e.DstIp, e.DstPort))
                    .Distinct()
                    .Count();

                if (distinctTargets >= profile.PortScanMinPorts)
                {
                    var minTime = windowGroup.Min(e => e.Timestamp);
                    var maxTime = windowGroup.Max(e => e.Timestamp);

                    findings.Add(new Finding
                    {
                        Category = "PortScan",
                        Severity = Severity.Medium,
                        SourceHost = srcIp,
                        Target = "multiple hosts/ports",
                        TimeRangeStart = minTime,
                        TimeRangeEnd = maxTime,
                        ShortDescription = $"Port scan detected from {srcIp}",
                        Details = $"Detected {distinctTargets} distinct destinations within {profile.PortScanWindowMinutes} minutes."
                    });
                }
            }
        }

        return findings;
    }
}
