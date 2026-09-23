# Day 07 — Week 1 Forensic Investigation

## Overview

Day 07 integrates the forensic concepts and practical techniques developed during the first week of the Digital Forensics and Incident Response (DFIR) lab.

The investigation uses a controlled case scenario involving suspicious document activity, PowerShell execution, executable creation, external network communication, removable USB activity, and access and deletion of a confidential spreadsheet.

The purpose is to reconstruct activity from multiple forensic evidence sources while distinguishing established facts, correlations, hypotheses, and unproven attribution.

## Case

**Case ID:** DFIR-2026-005

**Investigation Type:** Endpoint / Suspicious Execution / Potential Data Exposure

**Platform:** Windows Workstation

**User Context:** David

**Evidence Period:** 2026-09-23 09:19:41–09:27:12 +01:00

## Investigation Objectives

1. Determine what activity occurred.
2. Reconstruct when relevant events occurred.
3. Correlate evidence from independent sources.
4. Assess potentially suspicious execution.
5. Determine whether confidential information was potentially affected.
6. Assess possible USB involvement.
7. Distinguish account/session context from human attribution.
8. Document evidentiary limitations.

## Evidence Sources

Four controlled evidence sources were examined:

- Process execution evidence
- Filesystem evidence
- Network connection evidence
- USB device evidence

SHA-256 hashes were recorded as integrity baselines and later reverified.

## Reconstructed Timeline

| Time | Source | Event |
|---|---|---|
| 09:19:41 | Filesystem | Invoice-September.docm observed |
| 09:19:58 | Process | WINWORD.EXE executed with the document |
| 09:20:14 | Process | WINWORD.EXE spawned powershell.exe PID 5368 |
| 09:20:18 | Filesystem | update.exe created |
| 09:20:19 | Process | powershell.exe spawned update.exe |
| 09:20:25 | Network | PowerShell PID 5368 associated with 185.XX.XX.24:443 |
| 09:24:03 | USB | SanDisk Ultra USB device connected |
| 09:25:41 | Filesystem | Board-Financial-Plan-2027.xlsx accessed |
| 09:27:12 | Filesystem | Board-Financial-Plan-2027.xlsx deleted |

## Temporal Correlation

The reconstructed timeline contains nine events and eight intervals.

Key intervals:

- Document observed → Word execution: 17 seconds
- Word → PowerShell: 16 seconds
- PowerShell → update.exe creation: 4 seconds
- update.exe creation → execution: 1 second
- update.exe execution → recorded network activity: 6 seconds
- Network activity → USB connection: 218 seconds
- USB connection → spreadsheet access: 98 seconds
- Spreadsheet access → deletion: 91 seconds

Temporal proximity strengthens investigative correlation but does not independently establish causation.

## Process Findings

The evidence records the following process ancestry:

```text
explorer.exe
    ↓
WINWORD.EXE
    ↓
powershell.exe
    ↓
update.exe
```

WINWORD.EXE was recorded as the parent of PowerShell PID 5368, and PowerShell was subsequently recorded as the parent of update.exe.

These relationships strengthen the hypothesis that the events form a related execution sequence. They do not independently establish that Invoice-September.docm was malicious.

## Network Findings

PowerShell PID 5368 was associated with a TCP connection to:

```text
185.XX.XX.24:443
```

Recorded transfer:

```text
Bytes sent:     1,842
Bytes received: 5,276
```

The PID correlation connects the network activity to the same PowerShell process whose recorded parent was WINWORD.EXE.

The available evidence does not establish that the connection represented command-and-control or data exfiltration.

## USB Findings

A SanDisk Ultra USB mass-storage device was recorded as connected at 09:24:03.

The confidential spreadsheet was accessed 98 seconds later and deleted 91 seconds after access.

The USB connection preceded spreadsheet deletion by 189 seconds.

This temporal relationship supports further investigation of possible USB involvement but does not prove that the spreadsheet was copied to the removable device.

## Attribution Assessment

The evidence associates the activity with David's account, profile, and security context.

This supports **account/session attribution**.

It does not independently establish **human attribution**.

The evidence therefore does not establish that David personally initiated, intended, or physically performed the observed actions.

## Evidence Classification

The investigation classified 15 findings:

| Classification | Count |
|---|---:|
| Established Fact | 7 |
| Correlation | 2 |
| Hypothesis | 4 |
| Unproven Attribution | 2 |

This classification prevents investigative hypotheses from being presented as established forensic facts.

## Competing Hypotheses

### H1 — Document-Triggered Compromise

The document and subsequent process relationships may represent a document-triggered compromise.

### H2 — Legitimate or Benign Activity

Word, PowerShell, HTTPS communication, temporary executables, and USB devices can have legitimate uses. Malicious explanations therefore require independent evidentiary support.

### H3 — Compromised Process or Account Activity Without User Knowledge

Activity occurring under David's security context may have resulted from malicious or automated execution without intentional user involvement.

All three hypotheses remain subject to further testing.

## Evidence Integrity

Baseline SHA-256 hashes were recorded for:

- Filesystem-Evidence.csv
- Network-Evidence.csv
- USB-Evidence.csv
- Process-Evidence.csv

Post-analysis verification returned MATCH for all four evidence sources.

Matching hashes support evidence integrity between the baseline and post-analysis verification points. They do not establish evidence history before the baseline was created.

## Investigation Limitations

The current examination does not include:

- Full memory analysis
- Complete PowerShell script-block telemetry
- Detailed DOCM macro/VBA analysis
- Static or dynamic analysis of update.exe
- Packet-level network capture
- Forensic examination of the USB device
- Evidence proving the spreadsheet was copied to E:
- Evidence sufficient for human attribution

## Repository Structure

```text
Day-07-Week-1-Forensic-Investigation/
├── README.md
├── analysis/
│   ├── Evidence-Classification-Matrix.csv
│   ├── Evidence-Hash-Register.csv
│   ├── Normalized-Timeline.csv
│   └── Post-Analysis-Integrity-Check.csv
├── evidence/
│   ├── filesystem/
│   │   └── Filesystem-Evidence.csv
│   ├── network/
│   │   └── Network-Evidence.csv
│   ├── usb/
│   │   └── USB-Evidence.csv
│   └── volatile/
│       └── Process-Evidence.csv
├── notes/
└── report/
    └── DFIR-2026-005-Forensic-Investigation-Report.md
```

## Key Lessons

1. Build conclusions from evidence rather than suspicion.
2. Correlate independent evidence sources.
3. Do not treat temporal proximity as automatic causation.
4. Use process ancestry and PID correlation to strengthen analysis.
5. Distinguish network communication from proven C2 or exfiltration.
6. Distinguish account/session attribution from human attribution.
7. Verify evidence integrity throughout the investigation.
8. Maintain competing hypotheses to reduce confirmation bias.
9. Document investigative limitations.
10. State conclusions only to the level supported by the evidence.

## Forensic Principle

> **Observation → Correlation → Hypothesis → Testing → Defensible Conclusion**

A forensic investigator should be able to explain what the evidence establishes, what remains uncertain, and what additional evidence would be required to reduce that uncertainty.
