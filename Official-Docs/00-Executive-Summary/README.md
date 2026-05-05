# Executive Summary

You have 60 seconds. Here is what VulcansTrace is, what it proves, and where to go next.

---

## What Is VulcansTrace?

VulcansTrace is a Windows desktop tool that takes raw Windows Firewall logs through a full security analysis pipeline:

```
Raw log text --> Parsing --> Detection --> Correlation --> Escalation --> HMAC-signed evidence export
```

Every step runs locally. Logs never leave the machine.

---

## What Does It Prove?

That the builder understands the same pipeline that enterprise SIEM and XDR platforms implement at scale:

| Pipeline stage | What VulcansTrace does | Enterprise parallel |
|---|---|---|
| Log ingestion | Parses raw pfirewall.log text into structured records | Splunk / Sentinel data connectors |
| Behavioral detection | Six detectors: port scan, beaconing, lateral movement, flood, policy violation, novelty | CrowdStrike / Vectra / Darktrace detection modules |
| Cross-signal correlation | Multiple findings on the same host escalate severity | XDR correlation, Splunk risk-based alerting |
| Evidence packaging | SHA-256 hashes, HMAC-SHA256 manifest, deterministic ZIP builds | EnCase / Magnet AXIOM forensic packaging |

The detection algorithms are real implementations, not threshold-only alerts:

- **Beaconing detection** uses inter-arrival interval analysis with outlier trimming and standard deviation thresholds -- the same statistical foundation used in enterprise C2 detection
- **Port scan detection** uses a sliding-window algorithm with configurable time and target thresholds
- **Risk escalation** correlates independent detector outputs to increase confidence on a per-host basis

---

## Strongest Technical Parts

If a reviewer opens one thing, it should be one of these:

1. **[Beaconing Detection](../03-Beaconing-Detection/README.md)** -- Statistical C2 detection with configurable sensitivity. Maps to MITRE T1071.
2. **[Risk Escalation](../08-Risk-Escalation/README.md)** -- Cross-signal correlation that turns multiple weak signals into one strong signal. The core concept behind XDR.
3. **[Evidence Packaging](../09-Evidence-Packaging/README.md)** -- HMAC-SHA256 signed exports with per-file SHA-256, deterministic builds, and NIST/FRE alignment.

---

## By The Numbers

- **266 automated tests**, all passing -- covering parser, detectors, evidence packaging, and WPF workflows
- **0 build warnings, 0 build errors** in Release configuration
- **0 vulnerable NuGet packages** (including transitive)
- **~11,000 lines of C#** across 4 layered projects (Core, Engine, Evidence, Wpf)
- **6 detection categories** mapped to MITRE ATT&CK techniques
- **3 evidence export formats** (Markdown, HTML, CSV) with integrity protection
- **Performance benchmark**: 50K lines parsed and analyzed in ~482 ms (~103K lines/sec) on consumer hardware

---

## What Roles Does This Support?

| Role | What to focus on |
|---|---|
| SOC Analyst | Detection alerts, intensity tuning, evidence export workflow |
| Detection Engineer | Beaconing algorithm, port scan sliding window, risk escalation logic |
| Threat Hunter | Novelty detection, statistical beaconing analysis, MITRE ATT&CK mapping |
| Incident Responder | HMAC evidence packaging, forensic integrity, NIST SP 800-61 / FRE alignment |
| Security Engineer | Layered architecture, MVVM pattern, test coverage, clean separation of concerns |

---

## What This Project Does Not Claim

- It is not an enterprise SIEM replacement. It analyzes a single host's firewall logs.
- It is not a network tap or IDS. It works with whatever the Windows Firewall chose to log.
- Detection is threshold and statistics based, not ML-driven. Enterprise tools may use trained models for the same patterns.
- The HMAC signing key is ephemeral. Verifying evidence after export requires the key to have been preserved at export time.

---

## Where To Go Next

- **Quick path:** Read the three strongest modules linked above (Beaconing, Risk Escalation, Evidence Packaging), then browse the [full documentation index](../README.md).
- **Full path:** Start with [Log Parsing](../01-Log-Parsing/README.md) and read through all 12 modules in order.
- **Code path:** Open [VulcansTrace.sln](../../VulcansTrace.sln) and build it. Run the 266 tests. Read the detector source in VulcansTrace.Engine/Detectors/.
