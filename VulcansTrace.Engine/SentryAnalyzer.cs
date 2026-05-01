using VulcansTrace.Core;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;

namespace VulcansTrace.Engine;

/// <summary>
/// Orchestrates the complete log analysis pipeline from parsing through detection and risk escalation.
/// </summary>
/// <remarks>
/// This is the main entry point for log analysis. It coordinates:
/// <list type="bullet">
/// <item>Log parsing via <see cref="WindowsFirewallLogParser"/></item>
/// <item>Threat detection via multiple <see cref="IDetector"/> implementations</item>
/// <item>Risk escalation via <see cref="RiskEscalator"/></item>
/// <item>Severity filtering based on the analysis profile</item>
/// </list>
/// </remarks>
public sealed class SentryAnalyzer
{
    private const int MaxParseErrorsToKeep = 500;

    private readonly WindowsFirewallLogParser _parser;
    private readonly AnalysisProfileProvider _profileProvider;
    private readonly IReadOnlyList<IDetector> _detectors;
    private readonly RiskEscalator _riskEscalator;

    /// <summary>
    /// Initializes a new instance of the <see cref="SentryAnalyzer"/> class.
    /// </summary>
    /// <param name="parser">The log parser instance.</param>
    /// <param name="profileProvider">Provider for analysis profiles.</param>
    /// <param name="detectors">Collection of threat detectors to run.</param>
    /// <param name="riskEscalator">The risk escalation engine.</param>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public SentryAnalyzer(
        WindowsFirewallLogParser parser,
        AnalysisProfileProvider profileProvider,
        IEnumerable<IDetector> detectors,
        RiskEscalator riskEscalator)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _profileProvider = profileProvider ?? throw new ArgumentNullException(nameof(profileProvider));
        _detectors = detectors == null
            ? throw new ArgumentNullException(nameof(detectors))
            : detectors.ToList();
        _riskEscalator = riskEscalator ?? throw new ArgumentNullException(nameof(riskEscalator));
    }

    /// <summary>
    /// Performs a complete analysis of the provided log data.
    /// </summary>
    /// <param name="rawLog">The raw log file content to analyze.</param>
    /// <param name="intensity">The analysis intensity level (Low, Medium, High).</param>
    /// <param name="cancellationToken">Token to cancel the analysis operation.</param>
    /// <param name="overrideProfile">Optional custom profile to use instead of the standard intensity profile.</param>
    /// <returns>An <see cref="AnalysisResult"/> containing parsed entries, findings, and statistics.</returns>
    public AnalysisResult Analyze(string rawLog, IntensityLevel intensity, CancellationToken cancellationToken, AnalysisProfile? overrideProfile = null)
    {
        var result = new AnalysisResult();

        cancellationToken.ThrowIfCancellationRequested();

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors, cancellationToken);
        result.TotalLines = totalLines;
        result.IgnoredLines = ignoredLines;
        result.ParseErrorCount = parseErrors.Count;
        if (parseErrors.Count > MaxParseErrorsToKeep)
        {
            result.AddParseErrors(parseErrors.Take(MaxParseErrorsToKeep));
        }
        else
        {
            result.AddParseErrors(parseErrors);
        }
        result.ParsedLines = entries.Count;
        result.AddEntries(entries);

        if (entries.Count > 0)
        {
            result.TimeRangeStart = entries.Min(e => e.Timestamp);
            result.TimeRangeEnd = entries.Max(e => e.Timestamp);
        }

        var profile = overrideProfile ?? _profileProvider.GetProfile(intensity);

        var allFindings = new List<Finding>();
        var warnings = new List<string>();
        foreach (var detector in _detectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var detected = detector.Detect(entries, profile, cancellationToken);
                allFindings.AddRange(detected);

                if (detector is IProducesWarnings warnable && warnable.Warnings.Count > 0)
                {
                    warnings.AddRange(warnable.Warnings);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                warnings.Add($"Detector {detector.GetType().Name} crashed: {ex.Message}");
            }
        }

        // Suppress novelty findings from hosts already flagged for port scanning.
        // A port scanner's "novel" destinations are scan targets, not anomalies.
        var portScanSources = allFindings
            .Where(f => f.Category == "PortScan")
            .Select(f => f.SourceHost)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (portScanSources.Count > 0)
        {
            allFindings.RemoveAll(f => f.Category == "Novelty" && portScanSources.Contains(f.SourceHost));
        }

        var escalated = _riskEscalator.Escalate(allFindings);

        result.AddFindings(
            escalated.Where(f => f.Severity >= profile.MinSeverityToShow));
        result.AddWarnings(warnings);

        return result;
    }
}
