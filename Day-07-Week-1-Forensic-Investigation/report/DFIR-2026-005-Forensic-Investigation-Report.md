# DFIR-2026-005 — Week 1 Forensic Investigation Report

## 1. Executive Summary

A forensic examination was conducted following suspicious activity identified on a Windows workstation associated with the user account David.

The available evidence establishes a closely timed sequence involving a Microsoft Word document, PowerShell execution, creation and execution of an executable named update.exe, external network communication, USB device activity, and subsequent access and deletion of a confidential spreadsheet.

The evidence demonstrates significant temporal and process correlation. However, the current evidence does not independently establish that Invoice-September.docm was malicious, that the external connection represented command-and-control or data exfiltration, that the spreadsheet was copied to the USB device, or that David personally performed the observed actions.

Further forensic examination is therefore required before making definitive conclusions regarding compromise, data loss, or human attribution.

## 2. Case Information

- Case ID: DFIR-2026-005
- Investigation Type: Endpoint / Suspicious Execution / Potential Data Exposure
- Platform: Windows Workstation
- User Context: David
- Evidence Period: 2026-09-23 09:19:41–09:27:12 +01:00
- Analysis Method: Multi-source forensic artifact correlation

## 3. Evidence Sources

The investigation used four controlled evidence sources:

1. Process execution evidence
2. Filesystem evidence
3. Network connection evidence
4. USB device evidence

SHA-256 hashes were recorded for each evidence file before analysis.

Post-analysis verification confirmed that all four evidence files continued to match their recorded baseline hashes.

## 4. Timeline of Relevant Activity

| Time | Source | Event |
|---|---|---|
| 09:19:41 | Filesystem | Invoice-September.docm observed |
| 09:19:58 | Process | WINWORD.EXE executed with Invoice-September.docm |
| 09:20:14 | Process | WINWORD.EXE spawned powershell.exe PID 5368 |
| 09:20:18 | Filesystem | update.exe created in the user's Temp directory |
| 09:20:19 | Process | powershell.exe spawned update.exe |
| 09:20:25 | Network | PowerShell PID 5368 associated with 185.XX.XX.24:443 |
| 09:24:03 | USB | SanDisk Ultra USB mass-storage device connected |
| 09:25:41 | Filesystem | Board-Financial-Plan-2027.xlsx accessed |
| 09:27:12 | Filesystem | Board-Financial-Plan-2027.xlsx deleted |

## 5. Process Execution Findings

The process evidence records WINWORD.EXE executing with Invoice-September.docm in its command line.

Sixteen seconds later, WINWORD.EXE was recorded as the parent of powershell.exe PID 5368.

Four seconds after PowerShell execution was observed, update.exe was created in:

C:\Users\David\AppData\Local\Temp\update.exe

One second later, update.exe was recorded executing with powershell.exe as its parent.

These parent-child relationships and short time intervals provide strong correlation between the observed document activity, PowerShell execution, file creation, and subsequent executable activity.

The evidence does not, by itself, establish that Invoice-September.docm was malicious. Examination of document macros, embedded content, PowerShell telemetry, EDR/AMSI records, and update.exe would be required to further test that hypothesis.

## 6. Network Findings

At 09:20:25, powershell.exe PID 5368 was associated with a TCP connection to:

185.XX.XX.24:443

Recorded transfer:

- Bytes sent: 1,842
- Bytes received: 5,276

The PID correlation links the external connection to the same PowerShell process whose recorded parent was WINWORD.EXE.

This strengthens the hypothesis that the network activity was related to the preceding process chain.

The evidence does not establish the purpose or content of the communication. Therefore, the connection cannot currently be classified as confirmed command-and-control or data exfiltration.

## 7. USB and Confidential File Findings

A SanDisk Ultra USB mass-storage device was recorded as connected at 09:24:03 and mapped as drive E:.

The confidential spreadsheet:

C:\Users\David\Documents\Board-Financial-Plan-2027.xlsx

was recorded as accessed 98 seconds after USB connection and deleted 91 seconds after access.

USB connection therefore preceded spreadsheet deletion by 189 seconds.

This temporal proximity makes USB involvement a reasonable investigative hypothesis.

However, no current evidence establishes that the spreadsheet was copied or written to E:.

Confirmation would require evidence such as filesystem records from the USB device, source-to-destination file-operation telemetry, recoverable file content, or an intact matching copy of the spreadsheet on the removable media.

## 8. Attribution Assessment

The observed process activity occurred under the user context David.

Relevant filesystem artifacts were located under:

C:\Users\David\

USB evidence was also associated with David's user context.

These findings establish technical account/session context.

They do not establish that David personally initiated, intended, or physically performed the observed actions.

Malicious code, automated execution, remote activity, another individual using an authenticated session, or other mechanisms could potentially produce activity within the same security context.

Accordingly, human attribution remains unproven.

## 9. Evidence Classification

The investigation classified findings using four categories:

- Established Fact — directly supported by available evidence.
- Correlation — supported relationship between independently observed artifacts.
- Hypothesis — plausible explanation requiring additional evidence.
- Unproven Attribution — claim concerning a human actor that is not established by current evidence.

The classification matrix is maintained separately in:

analysis\Evidence-Classification-Matrix.csv

## 10. Competing Hypotheses

### H1 — Document-Triggered Compromise

The timing and process ancestry support the possibility that Invoice-September.docm initiated a malicious execution chain.

Further examination of the document, PowerShell activity, update.exe, endpoint telemetry, and network activity is required.

### H2 — Legitimate or Benign Activity with Coincidental Events

Word, PowerShell, HTTPS connections, temporary executables, and USB devices can all occur during legitimate activity.

The current evidence must therefore be tested against legitimate business or administrative explanations before malicious intent is concluded.

### H3 — Compromised Process or Account Activity Without David's Knowledge

The observed activity occurred within David's technical security context, but the Word-to-PowerShell process relationship provides a plausible mechanism for code to execute without David intentionally issuing the subsequent commands.

Additional user-interaction, authentication, remote-access, endpoint, and malware evidence would be necessary to distinguish intentional user activity from compromise.

## 11. Limitations

The current evidence does not include:

- Full memory acquisition and analysis
- Complete PowerShell script-block telemetry
- Analysis of Invoice-September.docm macros or embedded content
- Static or dynamic analysis of update.exe
- Packet-level network capture
- Confirmed ownership or reputation of the external destination
- Forensic image of the USB device
- Evidence proving a spreadsheet copy to E:
- Sufficient evidence for human attribution

These limitations constrain the conclusions that can currently be drawn.

## 12. Conclusion

The evidence establishes a strongly correlated sequence of document activity, PowerShell execution, executable creation and execution, external network communication, USB connection, and confidential spreadsheet activity.

The process ancestry and PID correlation provide stronger evidentiary value than temporal proximity alone.

However, the investigation has not yet established all causal links within the sequence.

Specifically, the current evidence does not prove that Invoice-September.docm was malicious, that the external communication constituted command-and-control or data exfiltration, that Board-Financial-Plan-2027.xlsx was copied to the USB device, or that David personally performed the observed actions.

The findings therefore support continued investigation rather than definitive attribution or a final determination of data exfiltration.

## 13. Forensic Principle

> Observation → Correlation → Hypothesis → Testing → Defensible Conclusion

Temporal proximity strengthens investigative hypotheses, but proximity alone does not establish causation.
