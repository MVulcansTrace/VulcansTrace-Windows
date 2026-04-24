namespace VulcansTrace.Core;

/// <summary>
/// Represents a security finding identified during log analysis.
/// </summary>
/// <remarks>
/// Immutable record created by detectors. Use <c>with</c> expression to create modified copies.
/// </remarks>
public sealed record Finding
{
    /// <summary>Unique identifier for this finding.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();
    
    /// <summary>Category of the finding (e.g., PortScan, Beaconing).</summary>
    public string Category { get; init; } = "";
    
    /// <summary>Severity level of the finding.</summary>
    public Severity Severity { get; init; }
    
    /// <summary>Source host IP address.</summary>
    public string SourceHost { get; init; } = "";
    
    /// <summary>Target of the activity (IP, port, or description).</summary>
    public string Target { get; init; } = "";
    
    /// <summary>Start of the activity time range.</summary>
    public DateTime TimeRangeStart { get; init; }
    
    /// <summary>End of the activity time range.</summary>
    public DateTime TimeRangeEnd { get; init; }
    
    /// <summary>Brief description of the finding.</summary>
    public string ShortDescription { get; init; } = "";
    
    /// <summary>Detailed information about the finding.</summary>
    public string Details { get; init; } = "";
}