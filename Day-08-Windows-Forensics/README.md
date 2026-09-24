# Day 08 — Windows Forensics

## Overview

Day 08 of the Digital Forensics & DFIR Lab focuses on identifying, preserving, analyzing, and correlating common Windows forensic artifacts.

The exercise demonstrates how multiple Windows artifact sources can be combined to reconstruct activity while distinguishing observation, correlation, hypothesis, causation, maliciousness, and human attribution.

---

## Case Information

**Case ID:** DFIR-2026-006  
**System:** DESKTOP-PCML6D5  
**Operating System:** Microsoft Windows 11 Pro  
**Build:** 22621  
**Examined Profile:** Ifean  
**Time Zone:** W. Central Africa Standard Time

---

## Objectives

The practical exercise covered:

- Windows forensic artifact identification
- Registry hive awareness
- Prefetch examination
- Windows Event Log analysis
- PowerShell Operational logging
- Event ID 4104 analysis
- Recent Items and LNK artifacts
- Controlled evidence acquisition
- SHA-256 integrity verification
- Cross-artifact temporal correlation
- Negative findings
- Acquisition limitations
- Defensible forensic interpretation

---

## Evidence Examined

| Evidence ID | Artifact | Acquisition Method |
|---|---|---|
| DFIR-D08-E001 | POWERSHELL.EXE-CA1AE517.pf | File copy |
| DFIR-D08-E002 | PowerShell-Operational-Events.csv | Derived CSV export |
| DFIR-D08-E003 | Day 8 Practical Lab Answer.docx.lnk | File copy |

### DFIR-D08-E001 — PowerShell Prefetch

Artifact:

`POWERSHELL.EXE-CA1AE517.pf`

SHA-256:

`88D5A522699DA8808BFB2A7DCCBFB7D2B596B13BB0A1B97E5F7B775E1F91B15D`

The source and acquired-copy hashes matched.

### DFIR-D08-E002 — PowerShell Operational Dataset

A derived CSV dataset was created from the Microsoft-Windows-PowerShell/Operational log using `Get-WinEvent`.

**Records retrieved:** 372  
**Event ID 4104 records:** 354

SHA-256:

`2BF0FB024302980E006F2D8CE9386604C2347863FDD0C017B1EEA5B71984190B`

This is a derived forensic dataset and not a bit-for-bit copy of the original EVTX file.

### DFIR-D08-E003 — Recent Items LNK

Artifact:

`Day 8 Practical Lab Answer.docx.lnk`

SHA-256:

`1AE1EF67753016C2E6283D143A0FEFA313370EB2E7EB3B110ED476B469D40ADE`

The source and acquired-copy hashes matched.

The LNK resolves to:

`C:\Users\Ifean\Desktop\30-Day Digital Forensic_DFIR Mentorship Roadmap\Day 8 Practical Lab Answer.docx`

---

## Key Findings

### PowerShell Prefetch

The PowerShell Prefetch artifact provides PowerShell execution-related evidence.

Observed filesystem metadata:

- CreationTime: 16/09/2026 13:23:30
- LastWriteTime: 17/09/2026 13:24:09

The filesystem LastWriteTime should not independently be interpreted as the exact process-start time.

The artifact does not independently establish command content, maliciousness, user intent, or human attribution.

### PowerShell Operational Events

The examined dataset contained:

| Event ID | Count |
|---|---:|
| 4104 | 354 |
| 4100 | 7 |
| 53504 | 5 |
| 4103 | 2 |
| 40961 | 2 |
| 40962 | 2 |

Available Event ID 4104 records ranged from:

- **First:** 15/09/2026 11:55:29
- **Last:** 21/09/2026 11:11:30

Searches for the following strings returned zero matches:

- Get-FileHash
- Copy-Item
- Get-WinEvent
- NTUSER.DAT
- Digital-Forensics-DFIR-Lab

This negative result does not prove that the associated commands were never executed. It establishes only that the specified strings were not identified within the examined Event ID 4104 evidence.

---

## Cross-Artifact Correlation

The PowerShell Prefetch artifact had a filesystem LastWriteTime of:

`17/09/2026 13:24:09`

PowerShell Operational records immediately preceding this timestamp included:

| Time | Event ID |
|---|---:|
| 13:23:59 | 40961 |
| 13:23:59 | 53504 |
| 13:24:00 | 40962 |

These independent artifacts are temporally consistent with PowerShell activity around the same period.

This supports temporal correlation but does not independently establish:

- the exact command executed;
- maliciousness;
- causation between a specific Event Log record and the Prefetch update;
- human intent; or
- exact process-start time.

---

## LNK Analysis

The acquired LNK resolves to the Day 8 practical lab document.

The artifact supports a shortcut/file-path relationship and provides useful user-activity context.

The LNK alone does not establish that the user read, edited, copied, or intentionally opened the document at a particular moment.

Additional corroborating artifacts would be required for stronger activity reconstruction or human attribution.

---

## Acquisition Limitations

Direct access to the following Registry hives returned Access Denied:

- SYSTEM
- SOFTWARE
- SAM
- SECURITY

This represents an access limitation and must not be interpreted as evidence that the Registry hives are absent.

`NTUSER.DAT` was identified at:

`C:\Users\Ifean\NTUSER.DAT`

Direct hashing and file-copy acquisition failed because the live loaded hive was in use.

This does not establish absence, corruption, tampering, or lack of relevant Registry evidence.

The Windows Security Event Log could not be queried because elevated privileges were required.

---

## Integrity Verification

| Evidence ID | Artifact | Result |
|---|---|---|
| DFIR-D08-E001 | PowerShell Prefetch | MATCH |
| DFIR-D08-E002 | PowerShell Operational derived dataset | MATCH |
| DFIR-D08-E003 | Day 8 LNK | MATCH |

**Evidence checked:** 3  
**Matches:** 3  
**Mismatches:** 0

No post-analysis integrity mismatch was identified.

---

## Forensic Reasoning

The exercise reinforced the following reasoning hierarchy:

**Artifact existence → Activity evidence → Temporal correlation → Contextual correlation → Hypothesis → Independent corroboration → Supported conclusion**

Technical association with an account, process, device, or artifact must not automatically be converted into attribution of knowledge, intent, or action to a human being.

**Execution is an observation. Suspicious or malicious activity is an interpretation requiring supporting context.**

---

## Repository Structure

~~~text
Day-08-Windows-Forensics/
├── analysis/
│   ├── Acquisition-Limitations.csv
│   ├── Evidence-Acquisition-Register.csv
│   ├── Post-Analysis-Integrity-Verification.csv
│   └── Windows-Artifact-Analysis-Matrix.csv
├── evidence/
│   ├── eventlogs/
│   │   └── PowerShell-Operational-Events.csv
│   ├── prefetch/
│   │   └── POWERSHELL.EXE-CA1AE517.pf
│   ├── registry/
│   └── user-activity/
│       └── Day 8 Practical Lab Answer.docx.lnk
├── notes/
├── report/
│   └── Day-08-Windows-Forensics-Report.md
└── README.md
~~~

---

## Key Lesson

Windows forensic artifacts are strongest when correlated with independent evidence.

No single artifact should automatically be treated as proof of maliciousness, causation, or human attribution.

**Forensic principle:**

> Observation → Correlation → Hypothesis → Corroboration → Supported Conclusion