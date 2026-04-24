using VulcansTrace.Core;
using VulcansTrace.Engine.Net;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Detects policy violations where internal hosts connect to disallowed external ports.
/// </summary>
/// <remarks>
/// Policy violations are identified when an internal host makes outbound connections to 
/// external destinations on ports that are explicitly prohibited (e.g., FTP/21, Telnet/23).
/// This may indicate unauthorized services, misconfigured applications, or policy non-compliance.
/// Note: Windows Firewall logs do not contain data volume, so actual data transfer cannot be detected.
/// </remarks>
public sealed class PolicyViolationDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnablePolicy || entries.Count == 0)
            return Enumerable.Empty<Finding>();

        var findings = new List<Finding>();
        var disallowed = new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>());

        foreach (var e in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!IpClassification.IsInternal(e.SrcIp))
                continue;

            if (!IpClassification.IsExternal(e.DstIp))
                continue;

            if (!e.DstPort.HasValue || !disallowed.Contains(e.DstPort.Value))
                continue;

            findings.Add(new Finding
            {
                Category = "PolicyViolation",
                Severity = Severity.High,
                SourceHost = e.SrcIp,
                Target = $"{e.DstIp}:{e.DstPort}",
                TimeRangeStart = e.Timestamp,
                TimeRangeEnd = e.Timestamp,
                ShortDescription = $"Disallowed outbound port from {e.SrcIp}",
                Details = $"Outbound connection to {e.DstIp}:{e.DstPort} on a disallowed port."
            });
        }

        return findings;
    }
}
