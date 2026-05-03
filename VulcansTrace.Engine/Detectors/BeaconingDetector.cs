using VulcansTrace.Core;
using VulcansTrace.Engine.Net;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Detects beaconing behavior indicating command-and-control (C2) communication.
/// </summary>
/// <remarks>
/// Beaconing is identified by regular, periodic connections from a host to the same 
/// external destination. The detector analyzes connection intervals for low variance,
/// which is characteristic of automated malware callbacks to C2 servers.
/// </remarks>
public sealed class BeaconingDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableBeaconing || entries.Count == 0)
            return Enumerable.Empty<Finding>();

        var findings = new List<Finding>();

        var byTuple = entries
            .Where(e => e.DstPort.HasValue && IpClassification.IsExternal(e.DstIp))
            .GroupBy(e => (SrcIp: e.SrcIp, DstIp: e.DstIp, DstPort: e.DstPort!.Value));

        foreach (var group in byTuple)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ordered = group.OrderBy(e => e.Timestamp).ToList();
            if (profile.BeaconMaxSamplesPerTuple > 0 && ordered.Count > profile.BeaconMaxSamplesPerTuple)
            {
                ordered = ordered.Skip(ordered.Count - profile.BeaconMaxSamplesPerTuple).ToList();
            }

            if (ordered.Count < profile.BeaconMinEvents)
                continue;

            var durationSeconds = (ordered[^1].Timestamp - ordered[0].Timestamp).TotalSeconds;
            if (durationSeconds < profile.BeaconMinDurationSeconds)
                continue;

            var intervals = new List<double>();
            for (int i = 1; i < ordered.Count; i++)
            {
                intervals.Add((ordered[i].Timestamp - ordered[i - 1].Timestamp).TotalSeconds);
            }

            if (intervals.Count == 0)
                continue;

            intervals.Sort();
            var trimmed = TrimIntervals(intervals, profile.BeaconTrimPercent);

            var mean = trimmed.Average();
            var variance = trimmed.Select(v => (v - mean) * (v - mean)).Average();
            var stdDev = Math.Sqrt(variance);

            if (mean < profile.BeaconMinIntervalSeconds || mean > profile.BeaconMaxIntervalSeconds)
                continue;

            if (stdDev > profile.BeaconStdDevThreshold)
                continue;

            var first = ordered.First();
            var last = ordered.Last();

            findings.Add(new Finding
            {
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = group.Key.SrcIp,
                Target = $"{group.Key.DstIp}:{group.Key.DstPort}",
                TimeRangeStart = first.Timestamp,
                TimeRangeEnd = last.Timestamp,
                ShortDescription = $"Regular beaconing from {group.Key.SrcIp}",
                Details = $"Average interval ~{mean:F1}s, std dev ~{stdDev:F1}s over {ordered.Count} events."
            });
        }

        return findings;
    }

    private static IReadOnlyList<double> TrimIntervals(IReadOnlyList<double> sortedIntervals, double trimPercent)
    {
        if (sortedIntervals.Count <= 2 || trimPercent <= 0)
            return sortedIntervals;

        var trimCount = (int)Math.Ceiling(sortedIntervals.Count * trimPercent);
        if (trimCount == 0)
            return sortedIntervals;

        var start = trimCount;
        var length = sortedIntervals.Count - (2 * trimCount);
        if (length <= 0)
            return sortedIntervals;

        return sortedIntervals.Skip(start).Take(length).ToList();
    }
}
