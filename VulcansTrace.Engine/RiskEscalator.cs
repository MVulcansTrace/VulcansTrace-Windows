using VulcansTrace.Core;

namespace VulcansTrace.Engine;

/// <summary>
/// Escalates finding severity when correlated threat patterns are detected.
/// </summary>
/// <remarks>
/// Currently detects the "Beaconing + Lateral Movement" pattern, which indicates
/// a likely compromised host communicating with a command-and-control server
/// while also probing internal systems. Such findings are escalated to Critical.
/// </remarks>
public sealed class RiskEscalator
{
    /// <summary>
    /// Processes findings and escalates severity when correlated threat patterns are detected.
    /// </summary>
    /// <param name="findings">The findings to evaluate for escalation.</param>
    /// <returns>
    /// A new collection of findings with escalated severities where applicable.
    /// Original findings are not modified; new instances are created using the <c>with</c> expression.
    /// </returns>
    public IReadOnlyList<Finding> Escalate(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
            return Array.Empty<Finding>();

        var result = new List<Finding>(findings.Count);

        var byHost = findings.GroupBy(f => f.SourceHost ?? string.Empty);
        foreach (var group in byHost)
        {
            var categories = group.Select(f => f.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var hasBeacon = categories.Contains("Beaconing");
            var hasLateral = categories.Contains("LateralMovement");
            var shouldEscalate = hasBeacon && hasLateral;

            foreach (var f in group)
            {
                if (shouldEscalate && f.Severity < Severity.Critical)
                    result.Add(f with { Severity = Severity.Critical });
                else
                    result.Add(f);
            }
        }

        return result;
    }
}