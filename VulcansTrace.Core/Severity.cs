namespace VulcansTrace.Core;

/// <summary>
/// Defines severity levels for security findings, ordered from least to most severe.
/// </summary>
public enum Severity
{
    /// <summary>Informational finding, no immediate action required.</summary>
    Info,
    
    /// <summary>Low severity finding, minor concern.</summary>
    Low,
    
    /// <summary>Medium severity finding, should be investigated.</summary>
    Medium,
    
    /// <summary>High severity finding, requires prompt attention.</summary>
    High,
    
    /// <summary>Critical severity finding, requires immediate action.</summary>
    Critical
}