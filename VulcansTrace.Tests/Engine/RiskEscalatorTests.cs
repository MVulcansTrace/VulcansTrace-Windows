using VulcansTrace.Core;
using VulcansTrace.Engine;
using Xunit;

namespace VulcansTrace.Tests.Engine;

public class RiskEscalatorTests
{
    private readonly RiskEscalator _escalator = new();

    [Fact]
    public void Escalate_WithEmptyFindings_ReturnsEmptyList()
    {
        // Arrange
        var findings = new List<Finding>();

        // Act
        var result = _escalator.Escalate(findings);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void Escalate_WithBeaconingOnly_NoEscalation()
    {
        // Arrange - Host with only Beaconing findings should not escalate
        var findings = new List<Finding>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "203.0.113.50:443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Regular beaconing",
                Details = "Beaconing detected"
            }
        };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert
        Assert.Single(result);
        Assert.Equal(Severity.Medium, result[0].Severity);
    }

    [Fact]
    public void Escalate_WithLateralMovementOnly_NoEscalation()
    {
        // Arrange - Host with only LateralMovement findings should not escalate
        var findings = new List<Finding>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Category = "LateralMovement",
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Lateral movement",
                Details = "Internal host scanning detected"
            }
        };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert
        Assert.Single(result);
        Assert.Equal(Severity.High, result[0].Severity);
    }

    [Fact]
    public void Escalate_WithBeaconingAndLateralMovementOnSameHost_EscalatesToCritical()
    {
        // Arrange - Host with both Beaconing and LateralMovement should escalate
        var beaconingFinding = new Finding
        {
            Id = Guid.NewGuid(),
            Category = "Beaconing",
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "203.0.113.50:443",
            TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
            TimeRangeEnd = DateTime.UtcNow,
            ShortDescription = "Regular beaconing",
            Details = "Beaconing detected"
        };

        var lateralFinding = new Finding
        {
            Id = Guid.NewGuid(),
            Category = "LateralMovement",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = DateTime.UtcNow.AddMinutes(-20),
            TimeRangeEnd = DateTime.UtcNow.AddMinutes(-5),
            ShortDescription = "Lateral movement",
            Details = "Internal host scanning detected"
        };

        var findings = new List<Finding> { beaconingFinding, lateralFinding };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_WithMixedFindings_EscalatesOnlyCorrectHost()
    {
        // Arrange - Multiple hosts, only one with both patterns should escalate
        var findings = new List<Finding>
        {
            // Host 1: Both patterns (should escalate)
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "203.0.113.50:443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Regular beaconing",
                Details = "Beaconing detected"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Category = "LateralMovement",
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-20),
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(-5),
                ShortDescription = "Lateral movement",
                Details = "Internal host scanning detected"
            },
            // Host 2: Only beaconing (should not escalate)
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "192.168.1.101",
                Target = "203.0.113.60:8443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-15),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Regular beaconing",
                Details = "Beaconing detected"
            }
        };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert
        Assert.Equal(3, result.Count);

        // Host 100 findings should be escalated to Critical
        var host100Findings = result.Where(f => f.SourceHost == "192.168.1.100").ToList();
        Assert.Equal(2, host100Findings.Count);
        Assert.All(host100Findings, f => Assert.Equal(Severity.Critical, f.Severity));

        // Host 101 finding should remain Medium
        var host101Findings = result.Where(f => f.SourceHost == "192.168.1.101").ToList();
        Assert.Single(host101Findings);
        Assert.Equal(Severity.Medium, host101Findings[0].Severity);
    }

    [Fact]
    public void Escalate_WithAlreadyCriticalFindings_PreservesCritical()
    {
        // Arrange - Findings already at Critical should remain Critical
        var findings = new List<Finding>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Beaconing",
                Severity = Severity.Critical,
                SourceHost = "192.168.1.100",
                Target = "203.0.113.50:443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Critical beaconing",
                Details = "Beaconing detected"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Category = "LateralMovement",
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-20),
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(-5),
                ShortDescription = "Lateral movement",
                Details = "Internal host scanning detected"
            }
        };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_WithEmptySourceHost_DoesNotCrash()
    {
        // Arrange - Handle findings with empty SourceHost gracefully
        var findings = new List<Finding>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "",
                Target = "203.0.113.50:443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Regular beaconing",
                Details = "Beaconing detected"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Category = "LateralMovement",
                Severity = Severity.High,
                SourceHost = "",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-20),
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(-5),
                ShortDescription = "Lateral movement",
                Details = "Internal host scanning detected"
            }
        };

        // Act & Assert - Should not throw
        var result = _escalator.Escalate(findings);

        // Both should escalate since they're grouped by empty SourceHost
        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_WithDifferentCategoryCasing_EscalatesCorrectly()
    {
        // Arrange - Test case-insensitive category matching
        var findings = new List<Finding>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Category = "beaconing", // lowercase
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "203.0.113.50:443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-10),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Regular beaconing",
                Details = "Beaconing detected"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Category = "LATERALMOVEMENT", // uppercase
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-20),
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(-5),
                ShortDescription = "Lateral movement",
                Details = "Internal host scanning detected"
            }
        };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert - Should still escalate due to case-insensitive comparison
        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_WithThirdCategoryOnCompromisedHost_EscalatesAllFindings()
    {
        // Arrange - Host with Beaconing + LateralMovement + third category (Novelty)
        // All findings should escalate to Critical, demonstrating "escalate ALL" behavior
        var findings = new List<Finding>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Beaconing",
                Severity = Severity.Medium,
                SourceHost = "192.168.1.50",
                Target = "203.0.113.50:443",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-30),
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "Regular beaconing",
                Details = "Beaconing detected"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Category = "LateralMovement",
                Severity = Severity.Medium,
                SourceHost = "192.168.1.50",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-25),
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(-5),
                ShortDescription = "Lateral movement",
                Details = "Internal host scanning detected"
            },
            new()
            {
                Id = Guid.NewGuid(),
                Category = "Novelty", // Third category - should also escalate
                Severity = Severity.Low,
                SourceHost = "192.168.1.50",
                Target = "new-external-host.example.com",
                TimeRangeStart = DateTime.UtcNow.AddMinutes(-15),
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(-10),
                ShortDescription = "First-time connection",
                Details = "Novel external destination detected"
            }
        };

        // Act
        var result = _escalator.Escalate(findings);

        // Assert - All three findings should be escalated to Critical
        Assert.Equal(3, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));

        // Verify specifically that the Low-severity Novelty finding was escalated
        var noveltyFinding = result.Single(f => f.Category == "Novelty");
        Assert.Equal(Severity.Critical, noveltyFinding.Severity);
    }
}