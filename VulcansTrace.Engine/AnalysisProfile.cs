using VulcansTrace.Core;

namespace VulcansTrace.Engine;

/// <summary>
/// Configuration profile controlling detector behavior and thresholds.
/// </summary>
/// <remarks>
/// Profiles are typically provided by <see cref="Configuration.AnalysisProfileProvider"/> based on intensity level,
/// but can be customized for specific analysis needs. Use the <c>with</c> expression to create modified copies.
/// </remarks>
public sealed record AnalysisProfile
{
    // Detector enable flags
    
    /// <summary>Gets or initializes whether port scan detection is enabled.</summary>
    public bool EnablePortScan { get; init; }
    
    /// <summary>Gets or initializes whether flood/DoS detection is enabled.</summary>
    public bool EnableFlood { get; init; }
    
    /// <summary>Gets or initializes whether lateral movement detection is enabled.</summary>
    public bool EnableLateralMovement { get; init; }
    
    /// <summary>Gets or initializes whether beaconing detection is enabled.</summary>
    public bool EnableBeaconing { get; init; }
    
    /// <summary>Gets or initializes whether policy violation detection is enabled.</summary>
    public bool EnablePolicy { get; init; }
    
    /// <summary>Gets or initializes whether novelty/anomaly detection is enabled.</summary>
    public bool EnableNovelty { get; init; }

    // Port scan thresholds
    
    /// <summary>Gets or initializes the minimum distinct ports to qualify as a port scan.</summary>
    public int PortScanMinPorts { get; init; }
    
    /// <summary>Gets or initializes the time window in minutes for port scan detection.</summary>
    public int PortScanWindowMinutes { get; init; }
    
    /// <summary>Gets or initializes the maximum entries to analyze per source IP (null for unlimited).</summary>
    public int? PortScanMaxEntriesPerSource { get; init; }

    // Flood thresholds
    
    /// <summary>Gets or initializes the minimum events to qualify as a flood.</summary>
    public int FloodMinEvents { get; init; }
    
    /// <summary>Gets or initializes the time window in seconds for flood detection.</summary>
    public int FloodWindowSeconds { get; init; }

    // Lateral movement thresholds
    
    /// <summary>Gets or initializes the minimum internal hosts contacted to qualify as lateral movement.</summary>
    public int LateralMinHosts { get; init; }
    
    /// <summary>Gets or initializes the time window in minutes for lateral movement detection.</summary>
    public int LateralWindowMinutes { get; init; }

    // Beaconing thresholds
    
    /// <summary>Gets or initializes the minimum events to analyze for beaconing.</summary>
    public int BeaconMinEvents { get; init; }
    
    /// <summary>Gets or initializes the maximum standard deviation for regular interval detection.</summary>
    public double BeaconStdDevThreshold { get; init; }
    
    /// <summary>Gets or initializes the minimum interval in seconds between beacons.</summary>
    public int BeaconMinIntervalSeconds { get; init; }
    
    /// <summary>Gets or initializes the maximum interval in seconds between beacons.</summary>
    public int BeaconMaxIntervalSeconds { get; init; }
    
    /// <summary>Gets or initializes the maximum samples to analyze per source/destination tuple.</summary>
    public int BeaconMaxSamplesPerTuple { get; init; }
    
    /// <summary>Gets or initializes the minimum duration in seconds for beaconing analysis.</summary>
    public int BeaconMinDurationSeconds { get; init; }
    
    /// <summary>Gets or initializes the percentage of outliers to trim from interval analysis.</summary>
    public double BeaconTrimPercent { get; init; }

    // Policy settings
    
    /// <summary>Gets or initializes the list of administrative ports to monitor for unauthorized access.</summary>
    public IReadOnlyList<int> AdminPorts { get; init; } = Array.Empty<int>();
    
    /// <summary>Gets or initializes the list of ports that should not allow outbound traffic.</summary>
    public IReadOnlyList<int> DisallowedOutboundPorts { get; init; } = Array.Empty<int>();

    // Output filtering
    
    /// <summary>Gets or initializes the minimum severity level for findings to be included in results.</summary>
    public Severity MinSeverityToShow { get; init; } = Severity.Medium;
}

