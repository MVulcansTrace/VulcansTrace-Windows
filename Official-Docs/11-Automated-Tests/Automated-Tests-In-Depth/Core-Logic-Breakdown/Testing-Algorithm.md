# Testing Algorithm

---

## The Security Problem

Security detectors fail in specific, predictable ways. A threshold set too low generates false positives that erode analyst trust. A threshold set too high misses real attacks. Statistical detectors fail when noise drowns the signal. The analysis pipeline fails when a crashing detector takes down the entire system. And tests that couple to implementation details fail when the implementation changes even though the behavior is correct.

Each failure mode requires a different testing approach. A single testing strategy cannot cover them all.

---

## Implementation Overview

A four-step testing strategy that maps each failure mode to a specific testing approach:

```text
Production Code
    |
    v
Step A: Threshold Boundary Tests ---- Why: Verify detector triggers at the right boundary
    |
    v
Step B: Statistical Detection Tests -- Why: Verify noise tolerance and signal extraction
    |
    v
Step C: Cancellation & Fault Tolerance - Why: Verify graceful degradation under pressure
    |
    v
Step D: Test Doubles & Isolation ------ Why: Verify orchestration independent of detectors
    |
    v
Confidence: Each detector fires when it should and stays silent when it should not
```

---

## Step A: Threshold Boundary Tests

**Process:** For each statistical detector, the test suite writes paired tests that verify the detector fires above the threshold and stays silent below it.

**Test pattern:**

```csharp
// PortScanDetectorTests.cs
[Fact]
public void Detect_WithPortScanAboveThreshold_ReturnsFinding()
{
    // Arrange: 20 distinct ports (above threshold of 15)
    var entries = new List<LogEntry>();
    for (int port = 1000; port < 1020; port++)
        entries.Add(new LogEntry { SrcIp = srcIp, DstPort = port, /* ... */ });

    var profile = new AnalysisProfile
    {
        EnablePortScan = true,
        PortScanMinPorts = 15,
        PortScanWindowMinutes = 5
    };

    // Act
    var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

    // Assert
    Assert.Single(findings);
    Assert.Equal("PortScan", findings[0].Category);
    Assert.Equal(Severity.Medium, findings[0].Severity);
}

// PortScanDetectorTests.cs
[Fact]
public void Detect_WithPortScanBelowThreshold_ReturnsNoFindings()
{
    // Arrange: 5 distinct ports (below threshold of 15)
    var entries = new List<LogEntry>();
    for (int port = 1000; port < 1005; port++)
        entries.Add(new LogEntry { SrcIp = srcIp, DstPort = port, /* ... */ });

    var profile = new AnalysisProfile
    {
        EnablePortScan = true,
        PortScanMinPorts = 15,
        PortScanWindowMinutes = 5
    };

    // Act
    var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

    // Assert
    Assert.Empty(findings);
}
```

**Rationale:** Paired threshold tests prevent either test alone from being insufficient — a detector that never fires passes every below-threshold test, and a detector that always fires passes every above-threshold test — proving the detector triggers at the correct boundary.

**Applied across detectors:**

| Detector | Test Type | Above-Threshold Test | Below-Threshold Test |
|----------|-----------|---------------------|---------------------|
| PortScan | Threshold | 20 ports > 15 | 5 ports < 15 |
| Beaconing | Statistical | Regular 90s intervals | Irregular mixed intervals |
| Flood | Threshold | High volume in window | Low volume in window |
| LateralMovement | Threshold | 8 internal hosts > 6 | 3 internal hosts < 6 |

**Rule-based detectors use scenario tests instead:**

```csharp
// PolicyViolationDetectorTests.cs
[Fact]
public void Detect_WithPolicyViolation_ReturnsFinding()
{
    // FTP on port 21 (disallowed) → Finding produced
}

[Fact]
public void Detect_WithAllowedPort_ReturnsNoFindings()
{
    // HTTPS on port 443 (allowed) → No findings
}
```

**Why the distinction:** Statistical detectors have numeric thresholds that need boundary calibration. Rule-based detectors have membership logic (allowed vs. disallowed) that needs scenario coverage. Different detection mechanisms need different test approaches.

---

## Step B: Statistical Validation Tests

**Process:** The BeaconingDetector uses statistical analysis (mean interval, standard deviation, outlier trimming) rather than a simple threshold. Testing it requires verifying that the statistics work correctly on noisy data.

**Test pattern:**

```csharp
// BeaconingDetectorTests.cs
[Fact]
public void Detect_WithRegularBeaconing_ReturnsFinding()
{
    // Arrange: 10 events at exactly 90-second intervals (stdDev ~0)
    var entries = new List<LogEntry>();
    for (int i = 0; i < 10; i++)
        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddSeconds(i * 90),
            SrcIp = srcIp, DstIp = dstIp, DstPort = dstPort, /* ... */
        });

    var profile = new AnalysisProfile
    {
        EnableBeaconing = true,
        BeaconMinEvents = 8,
        BeaconStdDevThreshold = 5.0,
        BeaconMinIntervalSeconds = 60,
        BeaconMaxIntervalSeconds = 900,
        BeaconMaxSamplesPerTuple = 200,
        BeaconMinDurationSeconds = 120,
        BeaconTrimPercent = 0.1
    };

    // Act
    var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

    // Assert
    Assert.Single(findings);
    Assert.Equal("Beaconing", findings[0].Category);
}

// BeaconingDetectorTests.cs
[Fact]
public void Detect_WithIrregularIntervals_ReturnsNoFindings()
{
    // Arrange: High-variance intervals (30, 180, 45, 300, 60, 240s)
    var intervals = new[] { 30, 180, 45, 300, 60, 240, 90, 150, 120 };
    var entries = new List<LogEntry>();
    var currentTime = baseTime;
    foreach (var gap in intervals)
    {
        entries.Add(new LogEntry
        {
            Timestamp = currentTime,
            SrcIp = srcIp, DstIp = dstIp, DstPort = dstPort, /* ... */
        });
        currentTime = currentTime.AddSeconds(gap);
    }

    // Act
    var findings = _detector.Detect(entries, profile, CancellationToken.None).ToList();

    // Assert
    Assert.Empty(findings);
}
```

**Rationale:** Statistical detection tests verify beaconing detection depends on interval variance, not just count — a C2 beacon at exactly 90 seconds has near-zero standard deviation, while legitimate traffic has high variance — ensuring the detector distinguishes periodic from random traffic.

**Additional statistical tests:**

```csharp
// BeaconingDetectorTests.cs — Outlier trimming
[Fact]
public void Detect_WithOutlierTrimStillFlagsBeacon()
{
    // 10 events with two outliers (5s and 300s) among regular 90s intervals
    // With BeaconTrimPercent = 0.2, outliers are trimmed
    // Beacon is still detected after trimming
}

// BeaconingDetectorTests.cs — Sample cap
[Fact]
public void Detect_RespectsSampleCap()
{
    // 300 events with BeaconMaxSamplesPerTuple = 50
    // Detector caps sampling and still produces one finding
}
```

---

## Step C: Robustness Tests

**Process:** The analysis pipeline runs multiple detectors sequentially. If one crashes, the others must continue. If the analyst cancels, the pipeline must stop promptly.

**Cancellation test:**

```csharp
// SentryAnalyzerRobustnessTests.cs
[Fact]
public void Analyze_WhenCancelledBeforeParsing_ThrowsOperationCanceled()
{
    var cts = new CancellationTokenSource();
    cts.Cancel();

    Assert.Throws<OperationCanceledException>(() =>
        analyzer.Analyze(rawLog, IntensityLevel.Low, cts.Token));
}
```

**Fault tolerance test:**

```csharp
// SentryAnalyzerRobustnessTests.cs
[Fact]
public void Analyze_WhenOneDetectorCrashes_ShouldContinueAndReportWarning()
{
    // CrashingDetector throws InvalidOperationException
    // WorkingDetector returns a valid High-severity finding
    var detectors = new IDetector[]
    {
        new CrashingDetector(),
        new WorkingDetector()
    };
    var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

    var result = analyzer.Analyze(rawLog, IntensityLevel.Low, CancellationToken.None);

    // The working detector's finding still appears
    Assert.Contains(result.Findings, f => f.Category == "Working");
    // A warning describes the crash
    Assert.Contains(result.Warnings, w => w.Contains("Detector crashed") && w.Contains("CrashingDetector"));
}
```

**Rationale:** Fault-tolerance tests ensure a security analysis pipeline that crashes when one detector throws an exception is unreliable in production — the entire analysis result would be lost — ensuring that a single broken detector does not prevent other detectors from producing findings.

**High-volume correctness test:**

```csharp
// SentryAnalyzerRobustnessTests.cs
[Fact]
public void Analyze_WithHighVolumeValidLog_CompletesAndTracksCounts()
{
    // 5,000 log lines generated in a StringBuilder
    var sb = new StringBuilder();
    for (var i = 0; i < 5000; i++)
    {
        var timestamp = new DateTime(2024, 1, 1, 0, 0, 0).AddSeconds(i);
        sb.AppendLine($"{timestamp:yyyy-MM-dd HH:mm:ss} ALLOW TCP 10.0.0.1 8.8.8.8 1000 53 OUTBOUND");
    }
    var log = sb.ToString().TrimEnd('\r', '\n');

    var result = analyzer.Analyze(log, IntensityLevel.Low, CancellationToken.None);

    // Verify line counts and time range boundaries
    Assert.Equal(5000, result.TotalLines);
}
```

---

## Step D: Orchestration Tests with Test Doubles

**Process:** When testing the analyzer's orchestration logic, real detector logic is a distraction. The test suite uses inline test doubles that implement `IDetector` and return predictable findings.

**FakeDetector pattern:**

```csharp
// SentryAnalyzerTests.cs
private class FakeDetector : IDetector
{
    public IEnumerable<Finding> Detect(
        IReadOnlyList<LogEntry> entries,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
    {
        yield return new Finding { Severity = Severity.Info, /* ... */ };
        yield return new Finding { Severity = Severity.Medium, /* ... */ };
        yield return new Finding { Severity = Severity.High, /* ... */ };
        yield return new Finding { Severity = Severity.Critical, /* ... */ };
    }
}
```

**Rationale:** Fakes test the outputs the analyzer produces from given detector inputs, not whether specific detector methods were called — fakes are simpler to maintain and easier to debug — testing orchestration behavior in isolation.

**Specialized test doubles:**

| Double | Location | Purpose |
|--------|----------|---------|
| `FakeDetector` | `SentryAnalyzerTests.cs` | Returns 4 findings at different severities for severity filtering tests |
| `CrashingDetector` | `SentryAnalyzerRobustnessTests.cs` | Throws `InvalidOperationException` for fault-tolerance testing |
| `WorkingDetector` | `SentryAnalyzerRobustnessTests.cs` | Returns one High-severity finding, continues when others crash |
| `EscalationTestDetector` | `SentryAnalyzerTests.cs` | Returns Beaconing + LateralMovement findings for escalation testing |
| `FakeDialogService` | `VulcansTrace.Tests/Wpf/FakeDialogService.cs` | Captures dialog messages, returns configurable save path |

---

## Step E: Evidence Integrity Tests

**Process:** The evidence builder packages analysis results into a ZIP with an HMAC-SHA256 signature. Tests verify the signature is cryptographically valid.

```csharp
// EvidenceBuilderTests.cs
[Fact]
public void Build_WithSigningKey_CreatesValidHmac()
{
    var zipBytes = builder.Build(result, rawLog, signingKey);

    // Extract manifest.json and manifest.hmac from ZIP
    var manifestBytes = /* extract from ZIP */;
    var hmacBytes = /* extract from ZIP */;

    // Verify HMAC is cryptographically valid
    var expectedHmac = hasher.ComputeHmacSha256(manifestBytes, signingKey);
    var expectedHmacHex = Convert.ToHexString(expectedHmac).ToLowerInvariant();
    var actualHmacHex = Encoding.UTF8.GetString(hmacBytes);

    Assert.Equal(expectedHmacHex, actualHmacHex);
}
```

**Rationale:** HMAC verification tests ensure security evidence is tamper-evident — if the manifest changes, the HMAC must be different — ensuring that evidence packages can be trusted during incident response.

---

## Complexity of the Test Suite

| Metric | Value |
|--------|-------|
| Test files | 23 |
| Test methods | 188 |
| Detector unit test files | 6 |
| Integration test files | 1 (parameterized) |
| Robustness test files | 1 |
| Evidence test files | 4 |
| WPF test files | 3 |
| Functional test files | 1 (`FunctionalTestRunner.cs`) |
| Test infrastructure files | 1 (`FakeDialogService.cs`) |
| Inline test doubles | 4 (inside test files) |

---

## Implementation Evidence

- [PortScanDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): above/below threshold, multi-source, truncation (285 lines)
- [BeaconingDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/BeaconingDetectorTests.cs): regular/irregular intervals, outlier trim, sample cap (552 lines)
- [LateralMovementDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/LateralMovementDetectorTests.cs): threshold, multi-source, time-spread (362 lines)
- [SentryAnalyzerTests.cs](../../../../VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs): severity filtering, risk escalation with test doubles (312 lines)
- [SentryAnalyzerIntegrationTests.cs](../../../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): cross-detector correlation, parameterized beacons (206 lines)
- [SentryAnalyzerRobustnessTests.cs](../../../../VulcansTrace.Tests/Engine/SentryAnalyzerRobustnessTests.cs): crash tolerance, cancellation, high-volume (109 lines)
- [EvidenceBuilderTests.cs](../../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): HMAC, ZIP structure, timestamp clamping, determinism (776 lines)

---

## Operational Impact

- Validates detection correctness across six detectors through threshold boundary tests, edge-case coverage, and integration scenarios
- Supports pipeline confidence by testing fault tolerance, cancellation behavior, and cross-detector escalation end-to-end
- Provides cryptographic integrity verification in automated tests so HMAC-SHA256 signing and SHA-256 hashing are continuously validated
---

## Security Takeaways

1. **Symmetric failure testing** — both below-threshold and above-threshold tests are mandatory
2. **Different detectors need different test strategies** — statistical detectors get boundary tests, rule-based detectors get scenario tests
3. **Fault tolerance is testable** — a crashing detector should not prevent other detectors from producing findings
4. **Evidence integrity is testable** — HMAC signatures can be verified programmatically
5. **Test doubles isolate concerns** — orchestration is tested independently of detector logic

