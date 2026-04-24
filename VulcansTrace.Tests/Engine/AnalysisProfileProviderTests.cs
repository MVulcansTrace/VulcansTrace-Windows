using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;

namespace VulcansTrace.Tests.Engine;

public class AnalysisProfileProviderTests
{
    private readonly AnalysisProfileProvider _provider = new();

    [Fact]
    public void GetProfile_Low_DisablesNoveltyAndHighMinSeverity()
    {
        // Act
        var profile = _provider.GetProfile(IntensityLevel.Low);

        // Assert
        Assert.False(profile.EnableNovelty);
        Assert.Equal(Severity.High, profile.MinSeverityToShow);
    }

    [Fact]
    public void GetProfile_Medium_EnablesAllDetectorsAndMediumMinSeverity()
    {
        // Act
        var profile = _provider.GetProfile(IntensityLevel.Medium);

        // Assert
        Assert.True(profile.EnablePortScan);
        Assert.True(profile.EnableFlood);
        Assert.True(profile.EnableLateralMovement);
        Assert.True(profile.EnableBeaconing);
        Assert.True(profile.EnablePolicy);
        Assert.True(profile.EnableNovelty);
        Assert.Equal(Severity.Medium, profile.MinSeverityToShow);
    }

    [Fact]
    public void GetProfile_High_LowerThresholdsAndInfoMinSeverity()
    {
        // Act
        var profile = _provider.GetProfile(IntensityLevel.High);

        // Assert
        Assert.True(profile.EnableNovelty);
        Assert.Equal(Severity.Info, profile.MinSeverityToShow);

        // High should have lower thresholds than Medium/Low
        Assert.Equal(8, profile.PortScanMinPorts);
        Assert.Equal(100, profile.FloodMinEvents);
        Assert.Equal(3, profile.LateralMinHosts);
    }

    [Fact]
    public void GetProfile_AllIntensities_SameAdminPortsAndDisallowedOutboundPorts()
    {
        // Act
        var lowProfile = _provider.GetProfile(IntensityLevel.Low);
        var mediumProfile = _provider.GetProfile(IntensityLevel.Medium);
        var highProfile = _provider.GetProfile(IntensityLevel.High);

        // Assert
        Assert.Equal(new[] { 445, 3389, 22 }, lowProfile.AdminPorts);
        Assert.Equal(new[] { 445, 3389, 22 }, mediumProfile.AdminPorts);
        Assert.Equal(new[] { 445, 3389, 22 }, highProfile.AdminPorts);

        Assert.Equal(new[] { 21, 23, 445 }, lowProfile.DisallowedOutboundPorts);
        Assert.Equal(new[] { 21, 23, 445 }, mediumProfile.DisallowedOutboundPorts);
        Assert.Equal(new[] { 21, 23, 445 }, highProfile.DisallowedOutboundPorts);
    }

    [Fact]
    public void GetProfile_BeaconingThresholds_MonotonicSensitivity()
    {
        // Act
        var low = _provider.GetProfile(IntensityLevel.Low);
        var medium = _provider.GetProfile(IntensityLevel.Medium);
        var high = _provider.GetProfile(IntensityLevel.High);

        // Assert - higher intensity is at least as sensitive (more permissive) as lower
        Assert.True(high.BeaconStdDevThreshold >= medium.BeaconStdDevThreshold);
        Assert.True(medium.BeaconStdDevThreshold >= low.BeaconStdDevThreshold);

        Assert.True(high.BeaconMinEvents <= medium.BeaconMinEvents);
        Assert.True(medium.BeaconMinEvents <= low.BeaconMinEvents);

        Assert.True(high.BeaconMinIntervalSeconds <= medium.BeaconMinIntervalSeconds);
        Assert.True(medium.BeaconMinIntervalSeconds <= low.BeaconMinIntervalSeconds);

        Assert.Equal(low.BeaconMaxIntervalSeconds, medium.BeaconMaxIntervalSeconds);
        Assert.Equal(medium.BeaconMaxIntervalSeconds, high.BeaconMaxIntervalSeconds);
    }

    [Fact]
    public void GetProfile_InvalidIntensity_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var invalidIntensity = (IntensityLevel)999;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            _provider.GetProfile(invalidIntensity));
        Assert.Equal("level", exception.ParamName);
    }

    [Theory]
    [InlineData(IntensityLevel.Low, 30)]
    [InlineData(IntensityLevel.Medium, 15)]
    [InlineData(IntensityLevel.High, 8)]
    public void GetProfile_PortScanThresholds_MatchExpectedValues(IntensityLevel level, int expectedMinPorts)
    {
        // Act
        var profile = _provider.GetProfile(level);

        // Assert
        Assert.Equal(expectedMinPorts, profile.PortScanMinPorts);
        Assert.Equal(5, profile.PortScanWindowMinutes); // Should be same across all profiles
    }

    [Theory]
    [InlineData(IntensityLevel.Low, 400)]
    [InlineData(IntensityLevel.Medium, 200)]
    [InlineData(IntensityLevel.High, 100)]
    public void GetProfile_FloodThresholds_MatchExpectedValues(IntensityLevel level, int expectedMinEvents)
    {
        // Act
        var profile = _provider.GetProfile(level);

        // Assert
        Assert.Equal(expectedMinEvents, profile.FloodMinEvents);
        Assert.Equal(60, profile.FloodWindowSeconds); // Should be same across all profiles
    }

    [Theory]
    [InlineData(IntensityLevel.Low, 6)]
    [InlineData(IntensityLevel.Medium, 4)]
    [InlineData(IntensityLevel.High, 3)]
    public void GetProfile_LateralMovementThresholds_MatchExpectedValues(IntensityLevel level, int expectedMinHosts)
    {
        // Act
        var profile = _provider.GetProfile(level);

        // Assert
        Assert.Equal(expectedMinHosts, profile.LateralMinHosts);
        Assert.Equal(10, profile.LateralWindowMinutes); // Should be same across all profiles
    }

    [Fact]
    public void GetProfile_PortScanMaxEntriesPerSource_DefaultsToUnbounded()
    {
        var low = _provider.GetProfile(IntensityLevel.Low);
        var medium = _provider.GetProfile(IntensityLevel.Medium);
        var high = _provider.GetProfile(IntensityLevel.High);

        Assert.Null(low.PortScanMaxEntriesPerSource);
        Assert.Null(medium.PortScanMaxEntriesPerSource);
        Assert.Null(high.PortScanMaxEntriesPerSource);
    }

    [Fact]
    public void GetProfile_WithExpression_CreatesIndependentCopy()
    {
        // Arrange
        var original = _provider.GetProfile(IntensityLevel.Low);
        
        // Act - create modified copy using with expression
        var modified = original with { PortScanMaxEntriesPerSource = 999 };
        
        // Assert - original should be unchanged
        Assert.Null(original.PortScanMaxEntriesPerSource);
        Assert.Equal(999, modified.PortScanMaxEntriesPerSource);
        
        // Other properties should be copied
        Assert.Equal(original.EnablePortScan, modified.EnablePortScan);
        Assert.Equal(original.PortScanMinPorts, modified.PortScanMinPorts);
        Assert.Equal(original.MinSeverityToShow, modified.MinSeverityToShow);
    }
}
