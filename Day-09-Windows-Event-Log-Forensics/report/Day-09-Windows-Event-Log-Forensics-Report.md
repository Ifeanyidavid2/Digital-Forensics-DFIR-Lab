# Day 09 — Windows Event Log Forensics Report

## Case Information

**Case ID:** DFIR-D09
**Host:** DESKTOP-PCML6D5
**Platform:** Windows 11
**Investigation:** Windows Event Log Forensics
**Examiner:** Ifeanyi David Ezechukwukere

---

## 1. Executive Summary

This investigation examined retained Windows Event Log evidence from DESKTOP-PCML6D5, with emphasis on System, PowerShell Operational, and Security logging.

Three EVTX evidence artifacts were acquired using `wevtutil epl` and baseline SHA-256 hashes were recorded. Post-analysis verification confirmed that all three acquired EVTX files retained their baseline hashes.

PowerShell Operational evidence contained extensive Event ID 4104 script-block logging. Initial keyword triage identified terms including `FromBase64String`, `Invoke-WebRequest`, `WebClient`, and the substring `IEX`. Reconstruction by ScriptBlockId substantially reduced raw record counts to logical script blocks and demonstrated that record-level keyword counts must not be interpreted as execution counts.

Contextual examination showed that the identified `FromBase64String`, `Invoke-WebRequest`, and `WebClient` references occurred within Exchange-related module content. The observed `FromBase64String` code decoded a warning-filtering value; the surfaced `Invoke-WebRequest` context related to HTTP timeout handling; and the surfaced `WebClient` reference occurred in an ExternalHelp filename. A standalone-token search did not identify an `IEX` token in the reconstructed logical blocks examined.

A separate PowerShell Event ID 4100 recorded an `Invoke-RestMethod` failure involving `get.activated.win`. System Event ID 1014 recorded a DNS timeout for the same domain approximately 66.6 milliseconds earlier and identified client PID 23160. This strongly supports a common failed name-resolution sequence involving PowerShell web activity. The examined evidence does not, however, establish that PID 23160 was powershell.exe, that an HTTP connection succeeded, that content was downloaded, that malware was retrieved, or that system compromise occurred.

Security.evtx was initially inaccessible from the non-elevated examination session and was subsequently acquired following controlled elevation. Its retained evidence begins on 22 September 2026 and therefore cannot corroborate the PowerShell and DNS activity observed on 16–17 September.

Authentication analysis identified 881 Event ID 4624 successful logon records and 16 Event ID 4625 failures. Fifteen failures were Logon Type 3 events from 10.226.76.181 occurring as five three-event clusters across multiple days. The pattern warrants investigation but does not independently establish brute-force activity. No successful Event ID 4624 from that source IP was identified in the retained evidence.

No Event ID 4688 or 1102 records were identified. At examination time, Process Creation auditing was configured as `No Auditing`, providing a plausible explanation for the absence of 4688 events. This current configuration does not independently establish the historical policy state throughout the retained evidence period.

Overall, the evidence establishes multiple security-relevant events and correlations but does not, by itself, establish malware execution, successful payload retrieval, attacker attribution, brute-force compromise, or system compromise.

## 2. Scope and Objectives

The objectives of the examination were to:

- Acquire relevant Windows Event Log evidence in a controlled manner.
- Establish cryptographic baselines for acquired evidence.
- Examine System and PowerShell Operational events.
- Analyze PowerShell Event IDs and script-block content.
- Reconstruct multi-part Event ID 4104 script blocks.
- Distinguish keyword occurrence from command execution.
- Correlate PowerShell activity with System and DNS events.
- Acquire and examine Security.evtx where permissions permitted.
- Analyze successful and failed authentication activity.
- Evaluate the absence of Event ID 4688 and Event ID 1102.
- Preserve evidentiary limitations and avoid unsupported attribution.

The investigation followed the principle:

**Evidence → Correlation → Conclusion**

and distinguished:

**Observation → Correlation → Hypothesis → Attribution**

## 3. Evidence Acquired

The following primary EVTX evidence artifacts were acquired:

| Evidence ID | Artifact | Acquisition Method | SHA-256 |
|---|---|---|---|
| DFIR-D09-E001 | System.evtx | wevtutil epl | 7444A75EF66FD923B344E578165DECCE6E60D8EC52AC39B5E4FB4AEE8E1CF026 |
| DFIR-D09-E002 | PowerShell-Operational.evtx | wevtutil epl | B3A68A4B5320E05E49EDD1B9385967ECC2C3F326B58C21A97C8B2C6541A1893F |
| DFIR-D09-E003 | Security.evtx | wevtutil epl following controlled elevation | 97B3A26141ED5ABE6F26D3B65043149E8FD34CF159D34BF2E14B9E91B57EF0F8 |

These files are treated as exported EVTX snapshots. The acquisition method does not by itself establish bit-for-bit identity with the underlying live log-storage representation.

## 4. Acquisition Limitations

Security.evtx could not initially be exported from the non-elevated PowerShell session because access was denied. Controlled elevation was subsequently used for read-only acquisition.

The acquired Security log contained 32,996 retained records with an evidence range beginning:

**22 September 2026 10:36:37 — Record ID 2118943**

and ending:

**25 September 2026 19:09:14 — Record ID 2151938**

Consequently, Security.evtx cannot corroborate events observed on 16–17 September because those dates fall outside its retained evidence range.

The initial non-elevated check of Process Creation audit policy also failed due insufficient privilege. A later elevated read-only query established that Process Creation was configured as `No Auditing` at examination time.

The registry path associated with process command-line auditing existed, but `ProcessCreationIncludeCmdLine_Enabled` was not present during the elevated examination. This describes the observed configuration at examination time and does not independently establish its historical state.

## 5. System Event Log Analysis

System.evtx contained 40,277 retained events.

The retained evidence range was:

- First retained record: Record ID 42176 — 30 December 2025 00:34:16.
- Last retained record: Record ID 82452 — 25 September 2026 12:00:00.

This represents the retained evidence range and must not be interpreted as the first or last activity that ever occurred on the host.

System lifecycle-related event counts included:

- Event ID 1074: 51
- Event ID 41: 7
- Event ID 6005: 52
- Event ID 6006: 45
- Event ID 6008: 7
- Event ID 7045: 24

Several recent sequences contained Event ID 41 followed by 6008 and 6005. These sequences support unexpected-shutdown/startup investigation but Event ID 41 alone does not establish malicious shutdown or a specific cause.

Event ID 7045 service-installation records included software and driver-related services. Service installation establishes that a service was installed; it does not, without additional evidence, establish malicious persistence.

## 6. PowerShell Event Log Analysis

PowerShell-Operational.evtx contained 376 retained events.

The Event ID distribution included:

| Event ID | Count |
|---|---:|
| 4104 | 354 |
| 4100 | 7 |
| 53504 | 7 |
| 40961 | 3 |
| 40962 | 3 |
| 4103 | 2 |

The retained Event ID 4104 range extended from 15 September through 25 September 2026.

Event ID 4104 establishes that script-block content was recorded by PowerShell logging. It does not independently establish that every string contained in the recorded content represents an executed command, malicious action, or successful operation.

## 7. Script-Block Reconstruction and Keyword Triage

The 354 Event ID 4104 records represented 14 unique ScriptBlockId values.

Of the 354 records, 350 belonged to multi-part script blocks.

Notable reconstructed blocks included:

- 149/149 parts — Teams `ProxyCmdletDefinitionsWithHelp.ps1`.
- 119/119 parts — Exchange temporary module `tmpEXO_3aaxdwt2.xkf.psm1`.
- 55/55 parts — Exchange temporary module `tmpEXO_idqxrjbx.en4.psm1`.
- 7/40 retained parts — Teams `Merged_custom_PsExt.ps1`.

The 7/40 block demonstrates incomplete retention and therefore cannot be treated as fully characterized.

Raw-record versus logical-block keyword counts included:

| Keyword | Raw Records | Logical Blocks |
|---|---:|---:|
| FromBase64String | 2 | 2 |
| Invoke-WebRequest | 6 | 2 |
| WebClient | 42 | 1 |
| IEX substring | 11 | 6 |

This demonstrates why raw Event ID 4104 keyword counts must not be described as command-execution counts.

Contextual analysis identified:

**FromBase64String**

The two complete Exchange temporary modules contained code decoding `$FilterWarningsInPagination` using UTF-8. The surrounding code described warning filtering associated with pagination. This context does not establish attacker-controlled Base64 payload execution or Base64-based evasion.

**Invoke-WebRequest**

The two logical blocks containing the term were Exchange temporary modules. Examined context included `X-ClientApplication = 'ExoManagementModule'` and a `Get-HttpTimeout` function described as returning HTTP timeout values for `Invoke-WebRequest`.

The occurrence of this term does not establish that malware was downloaded or that an Internet request successfully occurred.

**WebClient**

The logical block identified by triage contained:

`Microsoft.Exchange.WebClient-Help.xml`

within an ExternalHelp reference. This surfaced match does not establish .NET WebClient download activity.

**IEX**

Eleven raw records contained the substring `IEX`, distributed across six logical blocks. A standalone-token regex search identified zero standalone `IEX` tokens in the reconstructed blocks examined.

Therefore, the eleven substring hits do not establish eleven executions of `IEX` or `Invoke-Expression`.

## 8. DNS and PowerShell Correlation

A significant cross-artifact correlation was identified on 17 September 2026.

System Event ID 1014 occurred at:

**13:28:54.6857174**

and recorded:

- Query name: `get.activated.win`
- Result: DNS resolution timeout
- Client PID: 23160

PowerShell Event ID 4100 occurred at:

**13:28:54.7523490**

and recorded:

- Command Name: `Invoke-RestMethod`
- Host Application: `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`
- Error: `The remote name could not be resolved: 'get.activated.win'`

The events occurred approximately **66.6 milliseconds apart**, with the DNS event first.

The matching domain, compatible failure conditions, and extremely close temporal relationship strongly support interpretation as the same failed name-resolution sequence associated with PowerShell web activity.

However, the examined PowerShell Event ID 4100 did not expose a process ID that permits direct PID-to-PID correlation with DNS Client PID 23160.

The evidence therefore does not independently establish:

- that PID 23160 was powershell.exe;
- successful DNS resolution;
- successful HTTP communication;
- successful content retrieval;
- malware download;
- payload execution;
- attacker attribution; or
- system compromise.

An additional methodological finding is important: initial Event ID 4104 keyword triage returned zero `Invoke-RestMethod` matches, while Event ID 4100 directly identified `Invoke-RestMethod`. Therefore, zero keyword matches in one event type do not establish absence of the activity across other Windows event evidence.

## 9. Security Event Log Analysis

Security.evtx contained 32,996 retained records.

Selected event counts included:

- Event ID 4624: 881
- Event ID 4672: 859
- Event ID 4625: 16
- Event ID 4688: 0
- Event ID 1102: 0

Among Event ID 4624 records:

- Logon Type 5: 834
- Logon Type 11: 22
- Logon Type 7: 16
- Logon Type 2: 9

The successful-logon dataset was therefore dominated by Logon Type 5 service logons.

Recent Event ID 4672 records examined were associated with `NT AUTHORITY\SYSTEM` and Logon ID `0x3e7`.

Matching the reusable SYSTEM Logon ID alone is insufficient to associate those privileged-logon events with the investigator's elevated PowerShell session. Account context, temporal relationship, logon type, and surrounding evidence must also be considered.

## 10. Authentication Analysis

Sixteen Event ID 4625 failed-logon records were identified.

Fifteen were Logon Type 3 network failures from:

**10.226.76.181**

These fifteen events occurred as five three-event clusters between 22 and 24 September.

Within each recurring cluster, two events targeted `guest` approximately one to one-and-a-half seconds apart, followed by another failure with a blank target username.

The overall failure combinations included:

- 10 × Status `0xc000006e`, SubStatus `0xc0000072`
- 5 × Status `0xc000006d`, SubStatus `0xc0000064`
- 1 × Status `0xc000006d`, SubStatus `0xc000006a`

The final failure, on 25 September at 10:23:43, differed from the other fifteen:

- Logon Type: 2
- Source IP: not populated
- SubjectUserName: Ifean

It should therefore not automatically be grouped with the network-failure sequence.

No successful Event ID 4624 with source IP `10.226.76.181` was identified within the retained evidence.

The recurring network-authentication failures warrant further investigation, but the current evidence does not independently establish a brute-force attack or successful compromise.

## 11. Process Creation Auditing

No Event ID 4688 records were identified in the retained Security evidence.

A read-only elevated query of the current audit policy returned:

`Process Creation    No Auditing`

This provides a plausible explanation for the absence of Event ID 4688 records.

However, the current audit-policy state does not independently establish that Process Creation auditing remained disabled throughout the entire retained evidence period.

The `ProcessCreationIncludeCmdLine_Enabled` registry value was not present at examination time.

Consequently:

**Zero Event ID 4688 records must not be interpreted as evidence that no processes executed.**

## 12. Evidence Integrity Verification

Post-analysis SHA-256 verification was performed against all three source EVTX artifacts.

| Evidence ID | Artifact | Result |
|---|---|---|
| DFIR-D09-E001 | System.evtx | MATCH |
| DFIR-D09-E002 | PowerShell-Operational.evtx | MATCH |
| DFIR-D09-E003 | Security.evtx | MATCH |

All current hashes matched their acquisition baselines.

This supports the conclusion that the acquired EVTX evidence files remained unchanged between baseline hashing and post-analysis verification.

## 13. Forensic Timeline

A consolidated forensic timeline was created at:

`analysis/Day-09-Forensic-Timeline.csv`

SHA-256:

`65AF545F5BF318D6214086AE5CA6BF552F4B7E6FF7DDE7AB752BE93F2572ACD9`

Key timeline points include:

- 16 Sep 13:23:56 — PowerShell Event 4104 activity.
- 16 Sep 13:27:45 — Complete 119-part Exchange temporary module recorded.
- 17 Sep 13:24:09 — POWERSHELL.EXE Prefetch LastWriteTime.
- 17 Sep 13:28:54.6857174 — DNS timeout for `get.activated.win`.
- 17 Sep 13:28:54.7523490 — PowerShell `Invoke-RestMethod` resolution failure for the same domain.
- 22 Sep 10:36:37 — Beginning of retained Security evidence.
- 22 Sep 18:30:12 — First retained network-logon failure cluster from `10.226.76.181`.
- 25 Sep 10:23:43 — Distinct Logon Type 2 authentication failure.
- 25 Sep 19:11:05 — Security.evtx exported following controlled elevation.

## 14. Findings and Conclusions

### Finding 1 — PowerShell Script-Block Activity

Extensive PowerShell script-block logging was identified. Most records belonged to a small number of large multi-part logical script blocks.

**Conclusion:** Script-block activity is established. Record volume alone does not establish malicious activity.

### Finding 2 — Security-Relevant PowerShell Keywords

`FromBase64String`, `Invoke-WebRequest`, `WebClient`, and `IEX` substring hits were identified.

**Conclusion:** Contextual analysis did not establish malicious execution from those keyword hits. Keyword occurrence is an investigative lead rather than a forensic verdict.

### Finding 3 — PowerShell/DNS Failure Sequence

DNS Event 1014 and PowerShell Event 4100 referenced `get.activated.win` approximately 66.6 milliseconds apart.

**Conclusion:** The evidence strongly supports the same failed name-resolution sequence involving PowerShell web activity. Successful retrieval, malware download, payload execution, and compromise are not established.

### Finding 4 — Repeated Network Authentication Failures

Fifteen Event ID 4625 Type-3 failures originated from `10.226.76.181` in five recurring clusters.

**Conclusion:** The pattern warrants investigation but does not independently establish brute-force activity. No successful 4624 from that source was identified in the retained evidence.

### Finding 5 — Missing Process-Creation Events

No Event ID 4688 records were identified, and Process Creation auditing was observed as `No Auditing` at examination time.

**Conclusion:** The absence of 4688 is plausibly explained by logging configuration and must not be interpreted as absence of process execution.

### Finding 6 — Security Log Clearing

No Event ID 1102 records were identified.

**Conclusion:** No Security audit-log-clearing event was identified within the retained evidence. This does not establish that clearing never occurred outside the retained evidence period.

### Overall Conclusion

The Day 09 examination identified security-relevant PowerShell, DNS, authentication, service, and system activity and demonstrated several meaningful cross-artifact correlations.

The strongest correlation is the near-simultaneous DNS and PowerShell failure involving `get.activated.win`.

Nevertheless, the available evidence does not establish malware execution, successful malicious download, successful brute-force compromise, attacker attribution, or overall system compromise.

Further conclusions would require additional corroborating evidence.

## 15. Evidentiary Limitations

The investigation is subject to the following limitations:

1. Windows event logs use finite retention and circular logging; older records may have been overwritten.
2. Security.evtx begins on 22 September and cannot corroborate 16–17 September events.
3. Current audit configuration does not necessarily represent historical configuration.
4. Event ID 4104 content can contain functions, comments, help text, definitions, signatures, and code that was recorded without proving every contained operation executed.
5. One reconstructed Teams script block retained only 7 of 40 expected parts.
6. Keyword searches can produce substring and contextual false positives.
7. Zero keyword matches do not prove absence of a behavior.
8. The examined PowerShell 4100 record did not expose a PID allowing direct correlation to DNS Client PID 23160.
9. Event-log evidence alone may be insufficient to establish file content, network payloads, malware identity, user intent, or attacker attribution.
10. The acquisition used exported EVTX snapshots; it is not represented as a bit-for-bit copy of the live event-log storage mechanism.

## 16. Lessons Learned

This investigation demonstrated several core DFIR principles:

- An Event ID is evidence of a recorded event, not automatically evidence of maliciousness.
- Keyword hits are investigative leads, not conclusions.
- Raw Event ID 4104 records should be reconstructed into logical script blocks before counting apparent activities.
- Script content must be interpreted in context.
- Temporal correlation becomes stronger when combined with matching domains, accounts, identifiers, and compatible event semantics.
- Matching identifiers alone may be misleading when identifiers represent long-lived or reusable contexts.
- Absence of an event is meaningful only after considering logging configuration, retention, collection scope, and permissions.
- Current system configuration must not automatically be projected backward in time.
- Successful authentication does not automatically establish human-at-keyboard activity.
- Failed authentication does not automatically establish brute force.
- Evidence integrity should be verified before and after analysis.
- Forensic conclusions should remain within what the evidence actually establishes.

The guiding methodology remains:

**Observation → Correlation → Hypothesis → Testing → Supported Conclusion**

and:

**Evidence → Correlation → Conclusion**
