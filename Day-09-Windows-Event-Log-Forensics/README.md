# Day 09 — Windows Event Log Forensics

## Overview

Day 09 focuses on forensic acquisition, examination, correlation, and interpretation of Windows Event Log evidence.

The practical investigation examined System, PowerShell Operational, and Security event logs from a Windows 11 host while emphasizing an important DFIR principle:

> An event or keyword is evidence to investigate — not automatically proof of malicious activity.

The lab progressed from basic Event ID interpretation through PowerShell script-block reconstruction, authentication analysis, cross-artifact timeline correlation, and evidence-integrity verification.

## Learning Objectives

This lab demonstrates how to:

- Acquire Windows EVTX evidence using `wevtutil`.
- Establish SHA-256 evidence baselines.
- Query offline event logs with `Get-WinEvent`.
- Interpret Event IDs without overstating conclusions.
- Analyze System, PowerShell, and Security logs.
- Reconstruct multi-part PowerShell Event ID 4104 script blocks.
- Distinguish keyword occurrence from command execution.
- Analyze successful and failed Windows logons.
- Evaluate missing Event ID 4688 evidence against audit configuration.
- Correlate DNS and PowerShell activity.
- Build a defensible forensic timeline.
- Verify evidence integrity after analysis.
- Document acquisition and retention limitations.

## Case Information

| Field | Value |
|---|---|
| Case ID | DFIR-D09 |
| Host | DESKTOP-PCML6D5 |
| Platform | Windows 11 |
| Investigation | Windows Event Log Forensics |
| Examiner | Ifeanyi David Ezechukwukere |

## Evidence Acquired

Three primary EVTX artifacts were acquired.

| Evidence ID | Artifact | SHA-256 |
|---|---|---|
| DFIR-D09-E001 | System.evtx | `7444A75EF66FD923B344E578165DECCE6E60D8EC52AC39B5E4FB4AEE8E1CF026` |
| DFIR-D09-E002 | PowerShell-Operational.evtx | `B3A68A4B5320E05E49EDD1B9385967ECC2C3F326B58C21A97C8B2C6541A1893F` |
| DFIR-D09-E003 | Security.evtx | `97B3A26141ED5ABE6F26D3B65043149E8FD34CF159D34BF2E14B9E91B57EF0F8` |

The EVTX files were collected as exported event-log snapshots using `wevtutil epl`.

Post-analysis SHA-256 verification matched all three acquisition baselines.

## System Event Log Analysis

`System.evtx` contained **40,277 retained events**.

Selected event types included:

- Event ID 1074 — shutdown/restart initiation.
- Event ID 41 — unexpected restart/power-related condition.
- Event ID 6005 — Event Log service startup.
- Event ID 6006 — Event Log service shutdown.
- Event ID 6008 — unexpected shutdown.
- Event ID 7045 — service installation.
- Event ID 1014 — DNS Client name-resolution failure.

These events were interpreted according to their recorded context rather than being treated as automatically malicious.

## PowerShell Event Log Analysis

`PowerShell-Operational.evtx` contained **376 retained events**, including:

| Event ID | Count |
|---|---:|
| 4104 | 354 |
| 4100 | 7 |
| 53504 | 7 |
| 40961 | 3 |
| 40962 | 3 |
| 4103 | 2 |

The 354 Event ID 4104 records represented only **14 unique ScriptBlockId values**, demonstrating why raw event counts should not be interpreted as equivalent numbers of commands or activities.

One reconstructed Teams script block retained only **7 of 40 expected parts**, providing a practical example of incomplete log retention.

## PowerShell Keyword Triage

Initial record-level triage identified:

| Keyword | Raw Records | Logical Script Blocks |
|---|---:|---:|
| `FromBase64String` | 2 | 2 |
| `Invoke-WebRequest` | 6 | 2 |
| `WebClient` | 42 | 1 |
| `IEX` substring | 11 | 6 |

Contextual examination demonstrated that keyword occurrence alone did not establish malicious execution.

Examples included:

- `FromBase64String` in Exchange module warning-filtering code.
- `Invoke-WebRequest` references in Exchange HTTP-related helper content.
- `WebClient` appearing in `Microsoft.Exchange.WebClient-Help.xml`.
- `IEX` substring matches without a standalone `IEX` token in the reconstructed blocks examined.

### Key Lesson

**Keyword hit → investigative lead**

not:

**Keyword hit → malicious execution**

## DNS and PowerShell Correlation

A significant correlation was identified on **17 September 2026**.

### System Event ID 1014

- **Time:** `13:28:54.6857174`
- **Domain:** `get.activated.win`
- **Result:** DNS resolution timeout
- **Client PID:** `23160`

### PowerShell Event ID 4100

- **Time:** `13:28:54.7523490`
- **Command:** `Invoke-RestMethod`
- **Error:** Remote name could not be resolved: `get.activated.win`

The events occurred approximately **66.6 milliseconds apart**, with the DNS event occurring first.

The matching domain, timing, and compatible failure conditions strongly support interpretation as the same failed name-resolution sequence involving PowerShell web activity.

The evidence does **not** independently establish:

- PID 23160 was `powershell.exe`.
- Successful DNS resolution.
- Successful HTTP communication.
- Successful download.
- Malware retrieval.
- Payload execution.
- Attacker attribution.
- System compromise.

This correlation also demonstrates an important event-log lesson: Event ID 4104 keyword triage produced zero `Invoke-RestMethod` matches, while Event ID 4100 directly recorded `Invoke-RestMethod`.

Therefore:

> Zero keyword hits in one event type do not establish absence of the activity across other Windows event evidence.

## Security Event Log Analysis

`Security.evtx` contained **32,996 retained records**.

The retained Security evidence begins at:

- **Time:** `22 September 2026 10:36:37`
- **Record ID:** `2118943`
- **Event ID:** `4798`

The latest retained Security record examined was:

- **Time:** `25 September 2026 19:09:14`
- **Record ID:** `2151938`
- **Event ID:** `4672`

Because the retained Security evidence begins on 22 September 2026, it cannot corroborate the PowerShell and DNS activity examined from 16–17 September.

Selected Security Event IDs included:

| Event ID | Count |
|---|---:|
| 4624 | 881 |
| 4672 | 859 |
| 4625 | 16 |
| 4688 | 0 |
| 1102 | 0 |

The absence of an Event ID from the retained evidence is not equivalent to proof that the underlying activity never occurred.

## Successful Authentication Analysis

The 881 Event ID 4624 records were distributed primarily as:

| Logon Type | Count |
|---|---:|
| 5 | 834 |
| 11 | 22 |
| 7 | 16 |
| 2 | 9 |

The dominant activity was therefore **Logon Type 5 service logons**, primarily associated with the `SYSTEM` account.

This is important because a successful Event ID 4624 establishes that Windows recorded a successful logon event in the examined evidence. It does not, by itself, establish that a human user was actively operating the keyboard.

Recent Event ID 4672 records examined were associated with:

- Account: `SYSTEM`
- Domain: `NT AUTHORITY`
- Logon ID: `0x3e7`

These records should not be attributed to the investigator's elevated PowerShell session merely because they occurred during the investigation.

Matching a long-lived or reused SYSTEM Logon ID alone is insufficient for defensible event-to-event attribution.

## Failed Authentication Analysis

Sixteen Event ID 4625 failed-logon records were identified.

Fifteen were:

- **Logon Type:** `3`
- **Source IP:** `10.226.76.181`
- **Logon Process:** `NtLmSsp`

These fifteen failures occurred as **five recurring three-event clusters** across approximately two days.

Ten targeted the account:

- `guest`

Five contained a blank target username.

The recurring network failures warrant investigation, but the current evidence does **not** independently establish a brute-force attack.

A separate Event ID 4625 occurred on 25 September 2026 at `10:23:43` and differed from the network pattern:

- **Logon Type:** `2`
- **Logon Process:** `Advapi`
- **Subject User:** `Ifean`
- **Source IP:** not recorded as a remote address in the examined event

It was therefore analyzed separately rather than automatically grouped with the `10.226.76.181` activity.

## Successful Logon Correlation

Within the retained Security evidence:

- No successful Event ID 4624 was identified from `10.226.76.181`.
- No successful Event ID 4624 containing a non-placeholder remote IP was identified after excluding `-`, `::1`, and `127.0.0.1`.

This is a finding about the retained evidence only.

It does not establish that the source never authenticated successfully outside the retained period or through activity not represented in the examined records.

## Process Creation Auditing

No Event ID 4688 records were identified in the retained Security evidence.

An elevated read-only query of the current Windows audit configuration returned:

- **Audit Subcategory:** Process Creation
- **Current Setting:** `No Auditing`

This provides a plausible explanation for the absence of Event ID 4688 records.

However, the audit-policy result represents the configuration **at the time of examination on 25 September 2026**. It does not independently establish what the Process Creation audit configuration was throughout the entire retained Security-log period.

The registry path:

`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`

was present, while:

`ProcessCreationIncludeCmdLine_Enabled`

was not present at examination time.

Therefore:

> Zero Event ID 4688 records do not establish that no processes executed.

## Security Log Clearing

No Event ID 1102 records were identified in the retained Security evidence.

This supports the narrow conclusion that no Security audit-log-clearing Event ID 1102 was identified within the retained dataset.

It does **not** establish that the Security log was never cleared outside the retained evidence period.

## Evidence Integrity Verification

Post-analysis SHA-256 verification was performed against all three source EVTX acquisition baselines.

| Evidence ID | Artifact | Verification |
|---|---|---|
| DFIR-D09-E001 | System.evtx | MATCH |
| DFIR-D09-E002 | PowerShell-Operational.evtx | MATCH |
| DFIR-D09-E003 | Security.evtx | MATCH |

Matching post-analysis hashes support the conclusion that the acquired EVTX evidence remained unchanged during the analytical workflow.

The detailed verification record is stored in:

`analysis/Evidence-Integrity-Verification.csv`

## Forensic Timeline

A consolidated forensic timeline was created to correlate significant PowerShell, DNS, Prefetch, Security, authentication, and acquisition events.

The timeline is stored in:

`analysis/Day-09-Forensic-Timeline.csv`

SHA-256:

`65AF545F5BF318D6214086AE5CA6BF552F4B7E6FF7DDE7AB752BE93F2572ACD9`

Important timeline observations included:

- PowerShell script-block activity within the examined 16 September window.
- A complete 119-part Exchange temporary-module script block.
- PowerShell Prefetch temporal consistency on 17 September.
- DNS failure for `get.activated.win`.
- PowerShell `Invoke-RestMethod` failure involving the same domain approximately 66.6 milliseconds later.
- Security-log retained evidence beginning on 22 September.
- Repeated network authentication failures from `10.226.76.181`.
- Controlled acquisition of Security.evtx after elevation.

The timeline distinguishes recorded observations from analytical interpretation.

## Key Findings

1. **PowerShell script-block activity was established.**
   Event ID 4104 evidence contained substantial script-block content, but event volume alone did not establish malicious execution.

2. **Security-relevant PowerShell keywords required contextual analysis.**
   Raw keyword counts substantially overstated the number of logical script blocks containing those terms.

3. **DNS and PowerShell evidence strongly correlated.**
   System Event ID 1014 and PowerShell Event ID 4100 recorded the same unresolved domain within approximately 66.6 milliseconds.

4. **Repeated network authentication failures warrant investigation.**
   Fifteen Event ID 4625 network failures originated from `10.226.76.181` in five recurring clusters, but the retained evidence did not independently establish brute-force activity.

5. **No successful 4624 from the identified source was found in retained evidence.**
   This conclusion is limited to the retained Security dataset.

6. **No Event ID 4688 records were identified.**
   Current Process Creation auditing was configured as `No Auditing`, providing a plausible explanation without proving the historical configuration.

7. **No Event ID 1102 records were identified.**
   This establishes only that no Security-log-clearing event was identified within the retained evidence.

8. **Source evidence integrity was maintained.**
   All three acquired EVTX artifacts matched their acquisition SHA-256 baselines after analysis.

## Evidentiary Limitations

Important limitations include:

- Windows event logs were configured with finite retention and circular overwrite behavior.
- Security.evtx begins on 22 September 2026 and cannot corroborate activity from 16–17 September.
- Current audit configuration does not independently establish historical audit configuration.
- Event ID 4104 can contain definitions, comments, help content, signatures, and other script text that does not prove every contained operation executed.
- One reconstructed script block retained only 7 of 40 expected parts.
- Keyword searches can produce substring and contextual matches.
- Zero keyword hits do not establish absence of a technique.
- No PowerShell PID was available in the examined Event ID 4100 fields to directly associate DNS Client PID 23160 with powershell.exe.
- Absence of an Event ID in retained evidence does not prove the underlying activity never occurred.
- Event logs alone may be insufficient to establish malware attribution, user intent, or system compromise.

## Investigation Methodology

The Day 09 investigation followed the workflow:

**Preserve → Acquire → Hash → Verify → Parse → Reconstruct → Correlate → Interpret → Report**

For analytical conclusions:

**Observation → Correlation → Hypothesis → Testing → Supported Conclusion**

The guiding forensic principle remains:

> **Evidence → Correlation → Conclusion**

rather than:

> **Suspicion → Assumption → Conclusion**

## Repository Structure

The Day 09 investigation is organized as:

- `analysis/` — analytical datasets, correlation results, timeline, and integrity verification.
- `evidence/evtx/` — acquired EVTX evidence.
- `evidence/exports/` — derived event exports used during analysis.
- `notes/` — supporting investigative notes.
- `report/` — final professional forensic report.
- `README.md` — repository-facing investigation summary.

## Final Takeaway

Windows Event Logs can provide powerful evidence of authentication, system, PowerShell, and network-related activity, but reliable forensic interpretation depends on context and corroboration.

A log entry establishes what was recorded.

A keyword identifies something worth examining.

A timestamp establishes temporal placement.

A correlation strengthens a hypothesis.

Only sufficiently corroborated evidence supports a defensible forensic conclusion.
