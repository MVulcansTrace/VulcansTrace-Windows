using VulcansTrace.Core;
using VulcansTrace.Engine.Net;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Detects lateral movement patterns indicating internal network traversal by an attacker.
/// </summary>
/// <remarks>
/// Lateral movement is identified when an internal host connects to multiple other internal 
/// hosts on administrative ports (e.g., SMB/445, RDP/3389, SSH/22) within a time window.
/// This behavior suggests an attacker pivoting through the network after initial compromise.
/// <para>
/// <strong>MITRE ATT&CK Mapping:</strong> This detector maps to TA0008 (Lateral Movement) 
/// behaviors. It does NOT detect T1135 (Network Share Discovery), which involves enumeration 
/// commands (e.g., <c>net view</c>, <c>NetShareEnum()</c>) to list available shares. 
/// SMB port (445) usage is detected as part of lateral movement patterns, but share enumeration 
/// activity is not distinguished from normal SMB file access.
/// </para>
/// </remarks>
public sealed class LateralMovementDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableLateralMovement || entries.Count == 0)
            return Enumerable.Empty<Finding>();

        var findings = new List<Finding>();

        var adminPorts = profile.AdminPorts ?? Array.Empty<int>();
        var adminSet = new HashSet<int>(adminPorts);

        var filtered = entries.Where(e =>
            IpClassification.IsInternal(e.SrcIp) &&
            IpClassification.IsInternal(e.DstIp) &&
            e.DstPort.HasValue &&
            adminSet.Contains(e.DstPort.Value));

        var bySrc = filtered.GroupBy(e => e.SrcIp);
        foreach (var srcGroup in bySrc)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
            if (ordered.Count == 0) continue;

            var windowMinutes = profile.LateralWindowMinutes;

            int start = 0;
            for (int end = 0; end < ordered.Count; end++)
            {
                while (start < end &&
                       (ordered[end].Timestamp - ordered[start].Timestamp).TotalMinutes > windowMinutes)
                {
                    start++;
                }

                var hosts = ordered
                    .Skip(start)
                    .Take(end - start + 1)
                    .Select(e => e.DstIp)
                    .Distinct()
                    .ToList();

                if (hosts.Count >= profile.LateralMinHosts)
                {
                    var minTime = ordered[start].Timestamp;
                    var maxTime = ordered[end].Timestamp;

                    findings.Add(new Finding
                    {
                        Category = "LateralMovement",
                        Severity = Severity.High,
                        SourceHost = srcGroup.Key,
                        Target = "multiple internal hosts",
                        TimeRangeStart = minTime,
                        TimeRangeEnd = maxTime,
                        ShortDescription = $"Lateral movement from {srcGroup.Key}",
                        Details = $"Contacted {hosts.Count} internal hosts on admin ports."
                    });

                    break;
                }
            }
        }

        return findings;
    }
}
