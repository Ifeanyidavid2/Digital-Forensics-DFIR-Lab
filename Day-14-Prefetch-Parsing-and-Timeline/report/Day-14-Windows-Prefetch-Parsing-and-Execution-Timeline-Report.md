# Day 14 - Windows Prefetch Parsing and Execution Timeline

## 1. Executive Summary
This investigation examined CERTUTIL.EXE-28F1E0C1.pf using PECmd 2026.5.0. PECmd reported a run count of 10 and a last-run timestamp of 2026-10-15 14:21:50. An eight-record execution timeline CSV was exported and verified. A search of Security Event ID 4688 messages for certutil.exe between 14:15 and 14:30 on 15 October 2026 returned no matches. The current Process Creation audit policy was observed as No Auditing. These findings support recorded execution-related activity but do not establish user attribution, purpose, or maliciousness.

## 2. Objectives
- Parse a selected Prefetch artifact and validate the parser output.
- Extract execution-related timestamps into a structured timeline.
- Examine Security event logs for corroborating process-creation evidence.
- Document limitations and distinguish observations from interpretations.

## 3. Scope and Tools
- Source artifact: C:\Windows\Prefetch\CERTUTIL.EXE-28F1E0C1.pf
- Parser: PECmd 2026.5.0 by Eric Zimmerman.
- Parsed JSON: analysis\20261015145723_PECmd_Output.json
- Timeline CSV: analysis\CERTUTIL-Execution-Timeline.csv
- Audit-policy observation: analysis\Audit-Policy-Observation.csv
- Supporting files: analysis\Prefetch-Inventory.csv and analysis\Prefetch-SHA256-Manifest.csv
- The source Prefetch artifact was parsed in place; no forensic image acquisition is documented.

## 4. Prefetch Findings
- Executable name reported by PECmd: CERTUTIL.EXE.
- Prefetch filename identifier: 28F1E0C1; this is not a cryptographic integrity hash.
- File size reported by PECmd: 27,682 bytes.
- Run count reported by PECmd: 10.
- Last run reported by PECmd: 2026-10-15 14:21:50.
- Seven previous-run fields were exposed, with timestamps between 14:21:49 and 14:21:50 on 15 October 2026.
- PECmd reported ParsingError=False.
- The exported execution timeline CSV was verified to contain eight records: one LastRun and seven PreviousRun entries.

## 5. Security Log Corroboration
- Observed Security log range: 2026-10-15 12:14:25 (Record ID 2297102) to 2026-10-20 14:02:34 (Record ID 2330628).
- A search for Event ID 4688 messages mentioning certutil.exe between 2026-10-15 14:15:00 and 14:30:00 returned no matches.
- A separately inspected Event ID 4688 described lsass.exe with parent wininit.exe; it did not corroborate certutil.exe execution.
- The current Process Creation audit policy was reported as No Auditing and recorded at 2026-10-20 14:23:15 +01:00.
- The historical audit-policy state at the time of the reported Prefetch execution has not been established.

## 6. Inventory and Integrity Considerations
- The initial Prefetch inventory contained 430 lines, while the SHA-256 manifest contained 432 entries.
- Subsequent observations of the source directory also returned 432 Prefetch files.
- Two filenames appeared in the manifest comparison but not in the earlier inventory. The collection outputs were therefore not fully synchronized in time.
- The available observations do not establish why the source directory changed. These differences alone do not prove tampering.
- The SHA-256 manifest represents files observed during its own collection and should not be treated as a perfectly synchronized snapshot of the earlier inventory.

## 7. Assessment
The Prefetch artifact supports recorded execution-related activity associated with CERTUTIL.EXE. The Security log search did not provide a matching Event ID 4688 record in the searched interval. The current No Auditing setting may help explain limited process-creation evidence, but it does not establish the historical audit policy. The lack of a matching event is a corroboration gap, not proof that execution did not occur.
The reviewed artifact alone does not identify the user, establish command-line arguments, explain the purpose of execution, or demonstrate malicious activity. Referenced files and directories are parser-reported artifact metadata and do not independently prove causation.

## 8. Limitations
- The historical Process Creation audit policy has not been established.
- No matching Event ID 4688 for certutil.exe was found in the searched time window.
- The source Prefetch artifact was parsed in place; no forensic image acquisition is documented.
- The inventory and manifest reflect different observations of the source directory.
- Time-zone handling for parsed Prefetch timestamps has not been independently validated.
- No attribution or maliciousness determination can be made from the reviewed evidence alone.

## 9. Conclusion and Recommended Follow-up
The Prefetch parsing and timeline-export steps completed successfully. The artifact records execution-related activity associated with CERTUTIL.EXE, but the available evidence does not establish the user, command-line arguments, purpose, or maliciousness. Security Event ID 4688 did not provide corroboration in the searched interval. Further work should reconcile the inventory and manifest using a clearly timed collection and seek independent corroboration from available endpoint artifacts. Any additional conclusions should be grounded in records actually recovered and documented.

## 10. Supporting Files
- notes\Day-14-Investigation-Notes.md
- analysis\Prefetch-Inventory.csv
- analysis\Prefetch-SHA256-Manifest.csv
- analysis\20261015145723_PECmd_Output.json
- analysis\CERTUTIL-Execution-Timeline.csv
- analysis\Audit-Policy-Observation.csv

