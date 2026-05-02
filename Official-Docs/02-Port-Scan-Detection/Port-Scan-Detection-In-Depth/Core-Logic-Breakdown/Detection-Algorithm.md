# Detection Algorithm

---

## The Security Problem

Attackers perform port scanning to identify live hosts, discover open services, and find entry points for exploitation. In practice, the detector has to answer three questions repeatedly:

1. Which events belong to the same suspicious source?
2. Does that source show enough distinct destination breadth to matter?
3. Is the activity concentrated enough in time to look like reconnaissance rather than background noise?

The detector must answer those questions while keeping findings explainable and the analysis cost bounded.

---

## Implementation Overview

A 5-step detection pipeline implemented in [PortScanDetector.cs](../../../../VulcansTrace.Engine/Detectors/PortScanDetector.cs):

```text
Raw LogEntries
    |
    v
Step A: Feature Toggle ---------- Why: Skip if port scan detection is disabled
    |
    v
Step B: Group by Source IP --- Why: Identify single-source attacks
    |
    v
Step C: Global Threshold Check -- Why: Mathematical early-exit (skip noise)
    |
    v
Step D: Time Window Bucketing --- Why: Detect burst activity
    |
    v
Step E: Per-Window Detection ---- Why: Create findings for each aggressive window
    |
    v
Detector emits: Finding with Severity.Medium
    |
    v
Downstream (SentryAnalyzer pipeline):
  - RiskEscalator may escalate to Critical (if same source triggers Beaconing + LateralMovement)
  - MinSeverityToShow filter may hide findings (e.g., Low profile requires Severity.High)
    |
    v
User-visible findings in AnalysisResult
```

---

## Step A: Toggle Gate

**Process:** If `profile.EnablePortScan` is false or entries are empty, return immediately. The detector also validates that `profile.PortScanWindowMinutes > 0`; if zero or negative, it throws `ArgumentOutOfRangeException`.

**Rationale:** Zero-cost disable. Teams that don't need port scan detection pay nothing. The window validation is a guard against misconfigured custom profiles.

**Security Angle:** Defense in depth — the detector is one layer that can be toggled without affecting the rest of the pipeline.

---

## Step B: Source Grouping

**Process:** Entries without a destination port (e.g., ICMP) are excluded via a `DstPort.HasValue` filter. The remaining entries are grouped by source IP (`SrcIp`), then ordered by timestamp.

**Rationale:** Per-source analysis is fundamental to scan detection. A suspicious source typically scans from *one* IP — measuring *that source's* activity, not aggregating across all sources.

**Security Angle:** This step enables **source attribution** — isolating each IP's activity so the breadth and timing of the pattern can be measured. Note: the detector identifies the source IP, but cannot determine intent. An analyst must evaluate whether the source is an attacker, a compromised host, a NAT gateway, or a legitimate scanner before taking action.

The source IP is the key identifier for blocking, threat intelligence, and correlation with other security tools.

**Truncation (after grouping, if configured):**
The detector takes the first N entries chronologically (not random) to preserve earliest attack behavior and temporal context. The warning ensures analysts know data was limited.

---

## Step C: Global Threshold Check

**Process:** Before any time-window analysis, the detector counts distinct `(DstIp, DstPort)` tuples for the analyzed source set. If below threshold, the source is skipped entirely.

**Rationale:** This is a **mathematical early-exit optimization** when the full source set is analyzed. If a source has only 3 distinct targets globally, no single time window can exceed a threshold of 15. A subset cannot contain more distinct elements than the full set, so skipping that source does not introduce false negatives.

**Security Angle:** This also reduces unnecessary work on low-variety traffic. If a custom profile enables truncation before the pre-check, the detector is explicitly trading completeness for bounded per-source cost.

---

## Step D: Time Window Bucketing

**Process:** Each source's activity is divided into fixed, aligned time buckets.

**Rationale:** Bucketed windows provide simple implementation, O(n) performance after sorting, and predictable output. Real port scans are fast — most fit in one bucket.

---

## Step E: Per-Window Detection

**Process:** For each time bucket, the detector counts distinct targets. If the count is at or above threshold, a Finding is created.

Multiple findings are possible — if a source scans aggressively across multiple windows, each window exceeding threshold produces a separate finding.

**Security Angle:** The Finding structure gives analysts everything they need for triage: attribution (SourceHost), timeline (TimeRange), scope (Details), and severity.

---

## Complexity And Behavior

| Metric | Value | Why |
|--------|-------|-----|
| **Time (worst-case)** | O(n log n) | Sorting dominates |
| **Additional passes** | O(n) | Grouping, distinct counting, and per-window scans are linear once groups are built |
| **Space** | O(n) | Grouped entries in memory |
| **Global check** | O(n) | Single pass distinct count |

---

## Implementation Evidence

- [PortScanDetector.cs](../../../../VulcansTrace.Engine/Detectors/PortScanDetector.cs): grouping by source, distinct tuple counting, aligned time buckets, truncation, and finding emission
- [PortScanDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): above-threshold, below-threshold, multi-source, and truncation scenarios
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in presets that drive the detector's sensitivity
- [AnalysisProfileProviderTests.cs](../../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): verifies threshold values including 30, 15, and 8
