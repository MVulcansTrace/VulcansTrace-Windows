namespace VulcansTrace.Core;

/// <summary>
/// Contains the complete results of a log analysis operation.
/// </summary>
/// <remarks>
/// This class accumulates parsed log entries, detected findings, warnings, and statistics
/// during the analysis process. Collections are exposed as read-only; internal methods are
/// provided for population by the analysis engine.
/// </remarks>
public sealed class AnalysisResult
{
    private readonly List<LogEntry> _entries = [];
    private readonly List<Finding> _findings = [];
    private readonly List<string> _warnings = [];
    private readonly List<string> _parseErrors = [];

    /// <summary>Gets the collection of successfully parsed log entries.</summary>
    public IReadOnlyList<LogEntry> Entries => _entries;
    
    /// <summary>Gets the collection of security findings detected during analysis.</summary>
    public IReadOnlyList<Finding> Findings => _findings;
    
    /// <summary>Gets the collection of non-fatal warnings generated during analysis.</summary>
    public IReadOnlyList<string> Warnings => _warnings;
    
    /// <summary>Gets the collection of detailed parse error messages.</summary>
    public IReadOnlyList<string> ParseErrors => _parseErrors;

    /// <summary>Gets or sets the total number of lines in the input log.</summary>
    public int TotalLines { get; set; }
    
    /// <summary>Gets or sets the number of lines successfully parsed.</summary>
    public int ParsedLines { get; set; }
    
    /// <summary>Gets or sets the number of lines ignored (comments, headers, empty).</summary>
    public int IgnoredLines { get; set; }
    
    /// <summary>Gets or sets the count of lines that failed to parse.</summary>
    public int ParseErrorCount { get; set; }

    /// <summary>Gets or sets the earliest timestamp found in the log entries.</summary>
    public DateTime? TimeRangeStart { get; set; }
    
    /// <summary>Gets or sets the latest timestamp found in the log entries.</summary>
    public DateTime? TimeRangeEnd { get; set; }

    // Internal methods for population by the analysis engine and tests

    /// <summary>Adds a single log entry to the result.</summary>
    internal void AddEntry(LogEntry entry) => _entries.Add(entry);

    /// <summary>Adds multiple log entries to the result.</summary>
    internal void AddEntries(IEnumerable<LogEntry> entries) => _entries.AddRange(entries);

    /// <summary>Adds a single finding to the result.</summary>
    internal void AddFinding(Finding finding) => _findings.Add(finding);

    /// <summary>Adds multiple findings to the result.</summary>
    internal void AddFindings(IEnumerable<Finding> findings) => _findings.AddRange(findings);

    /// <summary>Adds a single warning to the result.</summary>
    internal void AddWarning(string warning) => _warnings.Add(warning);

    /// <summary>Adds multiple warnings to the result.</summary>
    internal void AddWarnings(IEnumerable<string> warnings) => _warnings.AddRange(warnings);

    /// <summary>Adds a single parse error to the result.</summary>
    internal void AddParseError(string error) => _parseErrors.Add(error);

    /// <summary>Adds multiple parse errors to the result.</summary>
    internal void AddParseErrors(IEnumerable<string> errors) => _parseErrors.AddRange(errors);
}

