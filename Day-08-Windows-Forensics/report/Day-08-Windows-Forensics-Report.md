# Day 08 — Windows Forensics Analysis Report

## Case Information

**Case ID:** DFIR-2026-006  
**Investigation:** Windows Forensic Artifact Analysis  
**System:** DESKTOP-PCML6D5  
**Operating System:** Microsoft Windows 11 Pro  
**Build:** 22621  
**Examined User Profile:** Ifean  
**Time Zone:** W. Central Africa Standard Time  

---

## 1. Objective

The objective of this exercise was to identify, preserve, examine, and correlate selected Windows forensic artifacts while maintaining evidentiary integrity and distinguishing observations from interpretation.

The investigation focused on:

- Windows Registry artifacts
- PowerShell Prefetch
- Windows PowerShell Operational Event Logs
- Recent Items / LNK artifacts
- Cross-artifact temporal correlation
- Evidence integrity verification
- Acquisition limitations

---

## 2. Evidence Examined

### DFIR-D08-E001 — PowerShell Prefetch

Artifact:

`POWERSHELL.EXE-CA1AE517.pf`

Source:

`C:\Windows\Prefetch\POWERSHELL.EXE-CA1AE517.pf`

Observed metadata:

- Size: 32,945 bytes
- CreationTime: 16/09/2026 13:23:30
- LastWriteTime: 17/09/2026 13:24:09

SHA-256:

`88D5A522699DA8808BFB2A7DCCBFB7D2B596B13BB0A1B97E5F7B775E1F91B15D`

The source and acquired-copy hashes matched.

---

### DFIR-D08-E002 — PowerShell Operational Event Dataset

A derived CSV dataset was created from the Microsoft-Windows-PowerShell/Operational log using Get-WinEvent.

Records retrieved:

`372`

Event distribution:

| Event ID | Count |
|---|---:|
| 4104 | 354 |
| 4100 | 7 |
| 53504 | 5 |
| 4103 | 2 |
| 40961 | 2 |
| 40962 | 2 |

Baseline SHA-256:

`2BF0FB024302980E006F2D8CE9386604C2347863FDD0C017B1EEA5B71984190B`

This CSV is a derived forensic dataset and is not a bit-for-bit copy of the original EVTX file.

---

### DFIR-D08-E003 — Recent Items LNK

Artifact:

`Day 8 Practical Lab Answer.docx.lnk`

Source:

`C:\Users\Ifean\AppData\Roaming\Microsoft\Windows\Recent\Day 8 Practical Lab Answer.docx.lnk`

Size:

`927 bytes`

SHA-256:

`1AE1EF67753016C2E6283D143A0FEFA313370EB2E7EB3B110ED476B469D40ADE`

The source and acquired-copy hashes matched.

The shortcut resolves to:

`C:\Users\Ifean\Desktop\30-Day Digital Forensic_DFIR Mentorship Roadmap\Day 8 Practical Lab Answer.docx`

Working directory:

`C:\Users\Ifean\Desktop\30-Day Digital Forensic_DFIR Mentorship Roadmap`

---

## 3. PowerShell Artifact Analysis

The PowerShell Operational dataset contained 372 records.

Event ID 4104 accounted for 354 records.

The available Event ID 4104 records ranged from:

- First: 15/09/2026 11:55:29
- Last: 21/09/2026 11:11:30

Searches were performed for:

- Get-FileHash
- Copy-Item
- Get-WinEvent
- NTUSER.DAT
- Digital-Forensics-DFIR-Lab

No matching Event ID 4104 records were identified for those search terms.

This negative result does not establish that the associated commands were never executed. It establishes only that the specified strings were not identified within the examined Event ID 4104 evidence.

---

## 4. Prefetch and Event Log Correlation

The PowerShell Prefetch artifact had a filesystem LastWriteTime of:

`17/09/2026 13:24:09`

PowerShell Operational records identified immediately before this timestamp included:

| Time | Event ID |
|---|---:|
| 13:23:59 | 40961 |
| 13:23:59 | 53504 |
| 13:24:00 | 40962 |

These independent artifacts are temporally consistent with PowerShell activity around 13:24 on 17 September 2026.

The correlation supports PowerShell execution/activity around that period.

It does not independently establish:

- the exact command executed;
- that the activity was malicious;
- that a particular Event Log record caused the Prefetch update;
- human intent; or
- that the Prefetch filesystem LastWriteTime represents the exact process-start time.

---

## 5. LNK Analysis

The acquired LNK references:

`Day 8 Practical Lab Answer.docx`

at:

`C:\Users\Ifean\Desktop\30-Day Digital Forensic_DFIR Mentorship Roadmap\Day 8 Practical Lab Answer.docx`

The LNK provides evidence of a file/path relationship and useful user-activity context associated with the document.

The artifact alone does not establish that the user:

- read the document contents;
- edited the document;
- copied the document;
- intentionally opened it at a particular moment; or
- personally performed every action associated with it.

Additional artifacts would be required for stronger reconstruction or human attribution.

---

## 6. Registry Acquisition Limitations

The following machine Registry hives could not be directly accessed in the current PowerShell session:

- SYSTEM
- SOFTWARE
- SAM
- SECURITY

The observed result was Access Denied due to insufficient privileges.

This must not be interpreted as evidence that the hives were absent.

`NTUSER.DAT` was identified at:

`C:\Users\Ifean\NTUSER.DAT`

Direct SHA-256 hashing and Copy-Item acquisition failed because the live loaded hive was in use by another process.

No partial destination copy was identified.

This represents a live-system acquisition limitation and does not establish corruption, tampering, or absence of relevant Registry evidence.

The Windows Security Event Log also could not be queried because elevated rights were required.

---

## 7. Integrity Verification

Post-analysis integrity verification was performed on all three preserved evidence items.

| Evidence ID | Artifact | Result |
|---|---|---|
| DFIR-D08-E001 | PowerShell Prefetch | MATCH |
| DFIR-D08-E002 | PowerShell Operational derived dataset | MATCH |
| DFIR-D08-E003 | Day 8 LNK | MATCH |

No post-analysis integrity mismatch was identified.

---

## 8. Forensic Assessment

The examined artifacts provide corroborating evidence of legitimate Windows and PowerShell activity on the system.

PowerShell Prefetch and PowerShell Operational Event Log records demonstrate that multiple independent Windows artifact sources can be correlated to strengthen an activity reconstruction.

The LNK artifact demonstrates how Windows Recent Items can provide file/path and user-activity context.

No evidence examined during this exercise independently establishes malicious PowerShell activity.

Similarly, no examined artifact is sufficient by itself to establish human intent or personal attribution.

The analysis demonstrates the importance of distinguishing:

**Artifact existence → Activity evidence → Temporal correlation → Contextual correlation → Hypothesis → Independent corroboration → Supported conclusion**

Technical attribution to an account, process, or device must also be distinguished from attribution of knowledge, intent, or action to a human being.

---

## 9. Conclusion

Day 08 demonstrated a defensible Windows forensic workflow involving artifact identification, controlled acquisition, hashing, integrity verification, analysis, cross-artifact correlation, documentation of negative findings, and explicit recording of acquisition limitations.

The investigation reinforces the principle that no single Windows artifact should automatically be treated as proof of maliciousness, causation, or human attribution.

**Forensic principle:**

> Observation → Correlation → Hypothesis → Corroboration → Supported Conclusion