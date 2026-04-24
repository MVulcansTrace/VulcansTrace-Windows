using VulcansTrace.Core;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Detects flood/denial-of-service (DoS) attacks based on high event volume.
/// </summary>
/// <remarks>
/// A flood is identified when a single source IP generates an unusually high number 
/// of connection events within a short time window, potentially indicating a DoS attack
/// or compromised host participating in a botnet.
/// <para>
/// <strong>Limitations:</strong> This detector analyzes Windows Firewall log patterns only.
/// It cannot confirm actual service disruption, business impact, or destructive activity.
/// Maps to MITRE ATT&CK T1498 (Network DoS) or T1499 (Endpoint DoS) as behavioral indicators only.
/// </para>
/// </remarks>
public sealed class FloodDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableFlood || entries.Count == 0)
            return Enumerable.Empty<Finding>();

        var findings = new List<Finding>();

        var bySrc = entries.GroupBy(e => e.SrcIp);
        foreach (var srcGroup in bySrc)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var srcIp = srcGroup.Key;

            var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
            if (ordered.Count == 0) continue;

            var windowSeconds = profile.FloodWindowSeconds;

            int start = 0;
            for (int end = 0; end < ordered.Count; end++)
            {
                while (start < end &&
                       (ordered[end].Timestamp - ordered[start].Timestamp).TotalSeconds > windowSeconds)
                {
                    start++;
                }

                int windowCount = end - start + 1;
                if (windowCount >= profile.FloodMinEvents)
                {
                    var minTime = ordered[start].Timestamp;
                    var maxTime = ordered[end].Timestamp;

                    findings.Add(new Finding
                    {
                        Category = "Flood",
                        Severity = Severity.High,
                        SourceHost = srcIp,
                        Target = "multiple hosts/ports",
                        TimeRangeStart = minTime,
                        TimeRangeEnd = maxTime,
                        ShortDescription = $"Flood detected from {srcIp}",
                        Details = $"Detected {windowCount} events within {windowSeconds} seconds."
                    });

                    break; // one finding per src is enough for v1
                }
            }
        }

        return findings;
    }
}