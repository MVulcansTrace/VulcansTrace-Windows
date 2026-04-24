using VulcansTrace.Core;

namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Defines the contract for threat detection algorithms.
/// </summary>
/// <remarks>
/// Implementations analyze log entries according to a specific detection strategy (e.g., port scans, beaconing).
/// </remarks>
public interface IDetector
{
    /// <summary>
    /// Analyzes log entries to detect security threats.
    /// </summary>
    /// <param name="entries">The log entries to analyze.</param>
    /// <param name="profile">The analysis profile containing detection thresholds.</param>
    /// <param name="cancellationToken">Token to cancel the detection operation.</param>
    /// <returns>An enumerable of findings representing detected threats.</returns>
    IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken cancellationToken);
}