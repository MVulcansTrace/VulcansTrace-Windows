using VulcansTrace.Core;
using VulcansTrace.Engine.Net;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Detects novel external destinations that appear only once in the log data.
/// </summary>
/// <remarks>
/// Novelty detection flags external IP:port combinations that have exactly one connection,
/// which may indicate reconnaissance, testing of new connections, or newly configured services.
/// Low severity but useful for deep forensic analysis.
/// Note: This does not detect exfiltration; firewall logs do not contain data volume information.
/// </remarks>
public sealed class NoveltyDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableNovelty || entries.Count == 0)
            return Enumerable.Empty<Finding>();

        var externalEntries = entries
            .Where(e => IpClassification.IsExternal(e.DstIp) && e.DstPort.HasValue)
            .ToList();
        if (externalEntries.Count == 0)
            return Enumerable.Empty<Finding>();

        var counts = externalEntries
            .GroupBy(e => (e.DstIp, e.DstPort!.Value))
            .ToDictionary(g => g.Key, g => g.Count());

        var findings = new List<Finding>();

        foreach (var e in externalEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var key = (e.DstIp, e.DstPort!.Value);
            if (counts[key] != 1)
                continue;

            findings.Add(new Finding
            {
                Category = "Novelty",
                Severity = Severity.Low,
                SourceHost = e.SrcIp,
                Target = $"{e.DstIp}:{e.DstPort}",
                TimeRangeStart = e.Timestamp,
                TimeRangeEnd = e.Timestamp,
                ShortDescription = "Novel external destination",
                Details = $"Single observed connection to {e.DstIp}:{e.DstPort}."
            });
        }

        return findings;
    }
}
