# Attack Scenario: Composite Attack Through the Test Suite

---

## The Attack

A compromised host (`10.0.0.20`) runs multiple attack patterns simultaneously:

```text
1. Port scanning:  8 distinct ports from one source
2. C2 beaconing:   Regular intervals (~60-70s) to external IP
3. Lateral movement: 3 internal hosts on admin ports
4. Policy violation: Outbound SMB (port 445)
5. Policy violation: Repeated outbound SMB (port 445)
6. Parse error:    One malformed line ("not-a-log-line")
```

This is not a hypothetical scenario — it is the test data from `SentryAnalyzerIntegrationTests.cs`.

---

## Test Construction

```csharp
// SentryAnalyzerIntegrationTests.cs
[Theory]
[MemberData(nameof(BeaconOffsetData))]
public void Analyze_WithCompositeSignals_EmitsFindingsAcrossDetectors(
    int[] beaconOffsets)
{
    var analyzer = CreateAnalyzer();
    var rawLog = BuildCompositeLog(beaconBase, beaconOffsets);

    var result = analyzer.Analyze(rawLog, IntensityLevel.High, CancellationToken.None);

    Assert.Equal(5, result.Findings.Count);
}
```

**The test runs twice** — once with beacon offsets `[0, 60, 122, 180]` and once with `[0, 70, 140, 210]` — to verify the pipeline handles different C2 timing patterns.

---

## Detection Walkthrough

### Step 1: Parsing

```text
Input:  Raw log text with one deliberate malformed line
Output: Parsed LogEntry list + 1 parse error

Parse error: "not-a-log-line" is recorded but does not stop analysis
All valid entries are parsed and passed to the detectors
```

### Step 2: Detector Execution

```text
PortScanDetector:      8 distinct ports → 1 finding (Category: PortScan, Severity: Medium)
BeaconingDetector:     Regular ~60-70s intervals → 1 finding (Category: Beaconing, Severity: Medium)
LateralMovementDetector: 3 internal hosts on admin ports → 1 finding (Category: LateralMovement, Severity: High)
PolicyViolationDetector: Two outbound SMB/445 events → 2 findings (Category: PolicyViolation, Severity: High)
NoveltyDetector:       No one-off external destinations in test data → no finding
```

### Step C: RiskEscalator Correlation

```text
Host 10.0.0.20 has:
  - Beaconing finding (Medium) → C2 communication
  - LateralMovement finding (High) → internal pivoting

RiskEscalator detects overlap → Escalate BOTH to Critical severity
```

**This is the highest-severity automated correlation the current pipeline produces.** External periodic communication plus internal pivoting from the same host is a high-confidence combination that the RiskEscalator promotes to Critical.

### Step 4: Severity Filtering

```text
Profile: IntensityLevel.High (MinSeverityToShow = Info)
All 5 findings pass the severity filter

Result: 5 findings returned to the caller
```

---

## The 5 Findings

```text
Finding 1: PortScan        Severity: Medium   Source: 10.0.0.10
Finding 2: Beaconing       Severity: Critical Source: 10.0.0.20  (escalated from Medium)
Finding 3: LateralMovement Severity: Critical Source: 10.0.0.20  (escalated from High)
Finding 4: PolicyViolation Severity: High     Source: 10.0.0.30  Target: 198.51.100.10:445
Finding 5: PolicyViolation Severity: High     Source: 10.0.0.30  Target: 198.51.100.10:445
```

---

## Additional Integration Tests

The same test file includes two more scenarios:

**Flood and Novelty across intensity levels:**

```csharp
// SentryAnalyzerIntegrationTests.cs
[Theory]
[InlineData(IntensityLevel.Medium, 1, 0)]
[InlineData(IntensityLevel.High, 2, 1)]
public void Analyze_FloodAndNoveltyAcrossIntensities(
    IntensityLevel intensity, int expectedFindings, int expectedNovelty)
{
    // Medium: 1 finding (Flood only, Novelty filtered out)
    // High: 2 findings (Flood + Novelty)
}
```

**Truncation warnings with override profile:**

```csharp
// SentryAnalyzerIntegrationTests.cs
[Fact]
public void Analyze_WithOverrideProfile_CollectsWarnings()
{
    var baseProfile = new AnalysisProfileProvider().GetProfile(IntensityLevel.High);
    var profile = baseProfile with
    {
        PortScanMaxEntriesPerSource = 5,
        PortScanMinPorts = 4
    };
    // Verifies truncation warnings appear in result
}
```

---

## Security Takeaways

1. **Composite attack testing is the strongest integration proof** — a single test verifies all detectors, escalation, and filtering
2. **RiskEscalator adds real security value** — Beaconing + LateralMovement on the same host escalates to Critical
3. **Parse resilience matters** — one malformed line does not stop the analysis
4. **Parameterized timing covers real-world variation** — C2 beacons don't always arrive at exactly 60 seconds
