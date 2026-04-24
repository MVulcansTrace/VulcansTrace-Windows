using VulcansTrace.Core;

namespace VulcansTrace.Engine.Configuration;

/// <summary>
/// Provides pre-configured analysis profiles based on intensity level.
/// </summary>
/// <remarks>
/// Each intensity level has carefully tuned thresholds:
/// <list type="bullet">
/// <item><see cref="IntensityLevel.Low"/>: Conservative, high thresholds, fewer findings</item>
/// <item><see cref="IntensityLevel.Medium"/>: Balanced thresholds for general use</item>
/// <item><see cref="IntensityLevel.High"/>: Aggressive, low thresholds, more findings</item>
/// </list>
/// </remarks>
public sealed class AnalysisProfileProvider
{
    /// <summary>
    /// Gets the analysis profile for the specified intensity level.
    /// </summary>
    /// <param name="level">The desired intensity level.</param>
    /// <returns>A configured <see cref="AnalysisProfile"/> with appropriate thresholds.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when an invalid intensity level is provided.</exception>
    public AnalysisProfile GetProfile(IntensityLevel level)
    {
        int[] adminPorts = [445, 3389, 22];
        int[] disallowedOutbound = [21, 23, 445];

        return level switch
        {
            IntensityLevel.Low => new AnalysisProfile
            {
                EnablePortScan = true,
                EnableFlood = true,
                EnableLateralMovement = true,
                EnableBeaconing = true,
                EnablePolicy = true,
                EnableNovelty = false,

                PortScanMinPorts = 30,
                PortScanWindowMinutes = 5,
                PortScanMaxEntriesPerSource = null,

                FloodMinEvents = 400,
                FloodWindowSeconds = 60,

                LateralMinHosts = 6,
                LateralWindowMinutes = 10,

                BeaconMinEvents = 8,
                BeaconStdDevThreshold = 3.0,
                BeaconMinIntervalSeconds = 60,
                BeaconMaxIntervalSeconds = 900,
                BeaconMaxSamplesPerTuple = 200,
                BeaconMinDurationSeconds = 120,
                BeaconTrimPercent = 0.1,

                AdminPorts = adminPorts,
                DisallowedOutboundPorts = disallowedOutbound,

                MinSeverityToShow = Severity.High
            },
            IntensityLevel.Medium => new AnalysisProfile
            {
                EnablePortScan = true,
                EnableFlood = true,
                EnableLateralMovement = true,
                EnableBeaconing = true,
                EnablePolicy = true,
                EnableNovelty = true,

                PortScanMinPorts = 15,
                PortScanWindowMinutes = 5,
                PortScanMaxEntriesPerSource = null,

                FloodMinEvents = 200,
                FloodWindowSeconds = 60,

                LateralMinHosts = 4,
                LateralWindowMinutes = 10,

                BeaconMinEvents = 6,
                BeaconStdDevThreshold = 5.0,
                BeaconMinIntervalSeconds = 30,
                BeaconMaxIntervalSeconds = 900,
                BeaconMaxSamplesPerTuple = 200,
                BeaconMinDurationSeconds = 120,
                BeaconTrimPercent = 0.1,

                AdminPorts = adminPorts,
                DisallowedOutboundPorts = disallowedOutbound,

                MinSeverityToShow = Severity.Medium
            },
            IntensityLevel.High => new AnalysisProfile
            {
                EnablePortScan = true,
                EnableFlood = true,
                EnableLateralMovement = true,
                EnableBeaconing = true,
                EnablePolicy = true,
                EnableNovelty = true,

                PortScanMinPorts = 8,
                PortScanWindowMinutes = 5,
                PortScanMaxEntriesPerSource = null,

                FloodMinEvents = 100,
                FloodWindowSeconds = 60,

                LateralMinHosts = 3,
                LateralWindowMinutes = 10,

                BeaconMinEvents = 4,
                BeaconStdDevThreshold = 8.0,
                BeaconMinIntervalSeconds = 10,
                BeaconMaxIntervalSeconds = 900,
                BeaconMaxSamplesPerTuple = 200,
                BeaconMinDurationSeconds = 120,
                BeaconTrimPercent = 0.1,

                AdminPorts = adminPorts,
                DisallowedOutboundPorts = disallowedOutbound,

                MinSeverityToShow = Severity.Info
            },
            _ => throw new ArgumentOutOfRangeException(nameof(level), level, null)
        };
    }
}
