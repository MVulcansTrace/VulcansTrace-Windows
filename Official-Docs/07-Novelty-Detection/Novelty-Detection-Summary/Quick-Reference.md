# Quick Reference

---

## Detection Algorithm (4 Steps)

Step A: Toggle Gate — Skip when EnableNovelty is false or input is empty
Step B: External Filter — Keep only external destinations with valid ports via `IpClassification.IsExternal`
Step C: Tuple Counting — GroupBy (DstIp, DstPort), ToDictionary with counts
Step D: Singleton Emission — Emit finding for each entry where count == 1

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnableNovelty | `false` | `true` | `true` |
| MinSeverityToShow | High | Medium | Info |
| Standalone Novelty Visible? | No (detector off) | No (Low < Medium) | Yes (Low >= Info) |

---

## Downstream Pipeline

```text
NoveltyDetector (Low)
    → RiskEscalator (Low → Critical if Beaconing + LateralMovement also present)
    → MinSeverityToShow filter (visible only at High intensity unless escalated)
```

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "Novelty" |
| Severity | Low (Critical if escalated) |
| SourceHost | e.SrcIp |
| Target | "{DstIp}:{DstPort}" |
| TimeRangeStart | e.Timestamp |
| TimeRangeEnd | e.Timestamp (same — single event) |
| ShortDescription | "Novel external destination" |
| Details | "Single observed connection to {DstIp}:{DstPort}." |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time | O(n) — linear scan |
| Space | O(n) worst case — O(e + u + f) |
| Sorting | None |
| Windowing | None |

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scope | External-only | Internal singletons are noise |
| Grouping key | (DstIp, DstPort) | Service-level granularity |
| Threshold | Count == 1 exactly | Precise semantics |
| Severity | Low | Deliberately weak signal |
| Visibility | Profile-gated | Analyst controls noise level |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|-----------|-----|----------|
| Network Service Discovery | T1046 | Weak — singleton probes |
| Application Layer Protocol | T1071 | Weak — initial C2 check-in |
| Dynamic Resolution | T1568 | Weak — rotating infrastructure |

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Multiple beacons | Missed | BeaconingDetector |
| Fast flux DNS | Partial | DNS analysis + correlation |
| Domain fronting | Missed | TLS inspection |
| Delay between beacons | Missed | Persistent first-seen database |
| Popular services | Missed | Threat intel enrichment |

---

## File References

| File | Purpose |
|------|---------|
| NoveltyDetector.cs | Detector implementation (57 lines) |
| IDetector.cs | Strategy interface |
| AnalysisProfile.cs | Configuration model |
| AnalysisProfileProvider.cs | Low/Medium/High presets |
| IpClassification.cs | External IP classification |
| RiskEscalator.cs | Cross-detector escalation |
| SentryAnalyzer.cs | Orchestrator and severity filter |
| NoveltyDetectorTests.cs | Unit test coverage (8 tests) |
| SentryAnalyzerIntegrationTests.cs | End-to-end visibility tests |
| RiskEscalatorTests.cs | Escalation test coverage |

