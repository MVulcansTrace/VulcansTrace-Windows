# Code Patterns

---

## Pattern 1: Arrange-Act-Assert (AAA)

```csharp
// PortScanDetectorTests.cs
[Fact]
public void Detect_WithPortScanAboveThreshold_ReturnsFinding()
{
    // Arrange
    var srcIp = "192.168.1.100";
    var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

    var entries = new List<LogEntry>();

    // Create 20 different destination ports from the same source within 5 minutes
    for (int port = 1000; port < 1020; port++)
    {
        entries.Add(new LogEntry
        {
            Timestamp = baseTime.AddMinutes(port % 3), // Spread within 5-minute window
            Action = "ALLOW",
            Protocol = "TCP",
            SrcIp = srcIp,
            SrcPort = 50000,
            DstIp = "10.0.0.1",
            DstPort = port,
            Direction = "INBOUND",
            RawLine = $"2024-01-01 12:{port % 3:00}:00 ALLOW TCP {srcIp} 50000 10.0.0.1 {port} INBOUND"
        });
    }

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
}
```

**Rationale:** The test suite uses AAA because the three-section structure makes test intent immediately visible — what was set up, what was executed, what was verified — for the purpose of making test failures easy to diagnose without reading the full test method.

**Where it appears:** Most detector unit tests follow AAA. Robustness tests vary — some use explicit AAA comments, others use a more compact style where the arrange/act boundary is less distinct.

---

## Pattern 2: Inline Test Doubles

```csharp
// SentryAnalyzerRobustnessTests.cs
private class CrashingDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken token)
    {
        throw new InvalidOperationException("Detector crashed!");
    }
}

private class WorkingDetector : IDetector
{
    public IEnumerable<Finding> Detect(IReadOnlyList<LogEntry> entries, AnalysisProfile profile, CancellationToken token)
    {
        return new[]
        {
            new Finding
            {
                Category = "Working",
                Severity = Severity.High,
                ShortDescription = "Working detector found something"
            }
        };
    }
}
```

**Rationale:** Inline test doubles serve specific test file needs — `CrashingDetector` tests fault tolerance, `FakeDetector` tests severity filtering — keeping test infrastructure co-located with the tests that consume it.

**All test doubles in the suite:**

| Double | File | Purpose |
|--------|------|---------|
| `FakeDetector` | `SentryAnalyzerTests.cs` | Returns 4 findings at different severities |
| `CrashingDetector` | `SentryAnalyzerRobustnessTests.cs` | Throws for fault-tolerance testing |
| `WorkingDetector` | `SentryAnalyzerRobustnessTests.cs` | Continues when others crash |
| `EscalationTestDetector` | `SentryAnalyzerTests.cs` | Returns Beaconing + LateralMovement for escalation |
| `BlockingDetector` | `MainViewModelIntegrationTests.cs` | Blocks detection with `ManualResetEventSlim` for snapshot timing tests |
| `FakeDialogService` | `Wpf/FakeDialogService.cs` | Captures dialog messages, avoids modal popups |

---

## Pattern 3: Parameterized Tests with MemberData

```csharp
// SentryAnalyzerIntegrationTests.cs
public static IEnumerable<object[]> BeaconOffsetData()
{
    yield return new object[] { new[] { 0, 60, 122, 180 } };
    yield return new object[] { new[] { 0, 70, 140, 210 } };
}

[Theory]
[MemberData(nameof(BeaconOffsetData))]
public void Analyze_WithCompositeSignals_EmitsFindingsAcrossDetectors(int[] beaconOffsets)
{
    // Test runs for each beacon pattern
}
```

**Rationale:** `[Theory]` with `[MemberData]` is used because beacon timing patterns vary in the real world and the detector must handle multiple patterns — validating the integration with different timing inputs without duplicating test methods.

---

## Pattern 4: Programmatic Test Data Construction

```csharp
// BeaconingDetectorTests.cs — building beacon entries inline
var entries = new List<LogEntry>();
var srcIp = "192.168.1.100";
var dstIp = "203.0.113.50";
var dstPort = 443;
var baseTime = new DateTime(2024, 1, 1, 12, 0, 0);

// Create 10 events with 90-second intervals (very regular, std dev will be ~0)
for (int i = 0; i < 10; i++)
{
    entries.Add(new LogEntry
    {
        Timestamp = baseTime.AddSeconds(i * 90),
        Action = "ALLOW",
        Protocol = "TCP",
        SrcIp = srcIp,
        SrcPort = 50000,
        DstIp = dstIp,
        DstPort = dstPort,
        Direction = "OUTBOUND",
        RawLine = $"2024-01-01 12:{i * 90 / 60:D2}:{(i * 90) % 60:D2} ALLOW TCP {srcIp} 50000 {dstIp} {dstPort} OUTBOUND"
    });
}
```

**Rationale:** Programmatic data constructors enable each test needs specific data shapes — exactly N ports, exactly M intervals, exactly K hosts — making test intent clear without cluttering the test method with data setup.

---

## Pattern 5: Full-Stack WPF Testing with STA Thread

```csharp
// MainViewModelIntegrationTests.cs
[Fact]
public async Task AnalyzeAndExportEvidence_PopulatesFindingsAndExports()
{
    var tcs = new TaskCompletionSource<bool>();
    var thread = new Thread(() =>
    {
        var dispatcher = Dispatcher.CurrentDispatcher;
        SynchronizationContext.SetSynchronizationContext(
            new DispatcherSynchronizationContext(dispatcher));

        dispatcher.InvokeAsync(async () =>
        {
            try
            {
                await RunScenarioAsync();
                tcs.SetResult(true);
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
            finally
            {
                dispatcher.InvokeShutdown();
            }
        });

        Dispatcher.Run();
    })
    { IsBackground = true };
    thread.SetApartmentState(ApartmentState.STA);

    thread.Start();
    await tcs.Task;
}
```

Inside `RunScenarioAsync()`, the test wires the parser, analyzer, evidence builder, and ViewModel path needed for the analyze-and-export workflow, then asserts on `vm.Findings.Items` and file existence with 2000ms polling timeouts.

**Rationale:** Full-stack WPF tests verify the desktop application's analyze + export workflow spans multiple layers — parser, analyzer, evidence builder, formatters, and file I/O — ensuring that the complete user workflow produces correct output.

---

## Pattern 6: HMAC Verification in Tests

```csharp
// EvidenceBuilderTests.cs
var expectedHmac = hasher.ComputeHmacSha256(manifestBytes, signingKey);
var expectedHmacHex = Convert.ToHexString(expectedHmac).ToLowerInvariant();
var actualHmacHex = Encoding.UTF8.GetString(hmacBytes);
Assert.Equal(expectedHmacHex, actualHmacHex);
```

**Rationale:** Programmatic HMAC verification ensures security evidence is tamper-evident — the test computes the expected HMAC and compares it byte-by-byte with the actual HMAC in the ZIP — ensuring the signing pipeline produces cryptographically valid signatures.

---

## Comparison Across Test Categories

| Pattern | Unit Tests | Integration Tests | Robustness Tests |
|--------|------------|-------------------|------------------|
| AAA layout | Explicit | Implicit (no comments) | Mixed (some explicit, some compact) |
| Test data | Programmatic | Composite log builder | High-volume builder |
| Test doubles | Real detectors (inline fakes for analyzer tests) | Real detectors | Crashing/working doubles |
| Assertions | Finding count/severity | Cross-detector correlation | Warnings + continuation |
| Parameterization | Rare | `[Theory]` + `[MemberData]` | None |

---

## Security Takeaways

1. **AAA makes test intent visible** — failures are easy to diagnose without reading the full method
2. **Inline test doubles keep infrastructure co-located** — each double lives with the tests that use it
3. **Parameterized tests cover multiple attack patterns** — one method, multiple beacon timings
4. **Full-stack WPF tests verify the user workflow** — from log text to exported ZIP
5. **HMAC verification checks post-export evidence integrity** — cryptographic signatures tested programmatically
