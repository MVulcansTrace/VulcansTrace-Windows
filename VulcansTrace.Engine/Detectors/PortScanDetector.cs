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

            var window = TimeSpan.FromMinutes(profile.PortScanWindowMinutes);
            var targetCounts = new Dictionary<(string DstIp, int? DstPort), int>();
            var end = 0;
            for (var start = 0; start < ordered.Count; start++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                while (end < ordered.Count && ordered[end].Timestamp - ordered[start].Timestamp <= window)
                {
                    var target = (ordered[end].DstIp, ordered[end].DstPort);
                    targetCounts[target] = targetCounts.TryGetValue(target, out var count) ? count + 1 : 1;
                    end++;
                }

                if (targetCounts.Count >= profile.PortScanMinPorts)
                {
                    var minTime = ordered[start].Timestamp;
                    var maxTime = ordered[end - 1].Timestamp;

                    findings.Add(new Finding
                    {
                        Category = "PortScan",
                        Severity = Severity.Medium,
                        SourceHost = srcIp,
                        Target = "multiple hosts/ports",
                        TimeRangeStart = minTime,
                        TimeRangeEnd = maxTime,
                        ShortDescription = $"Port scan detected from {srcIp}",
                        Details = $"Detected {targetCounts.Count} distinct destinations within {profile.PortScanWindowMinutes} minutes."
                    });

                    targetCounts.Clear();
                    start = end - 1;
                    continue;
                }

                var expiredTarget = (ordered[start].DstIp, ordered[start].DstPort);
                if (targetCounts[expiredTarget] == 1)
                    targetCounts.Remove(expiredTarget);
                else
                    targetCounts[expiredTarget]--;
            }
        }

        return findings;
    }
}
