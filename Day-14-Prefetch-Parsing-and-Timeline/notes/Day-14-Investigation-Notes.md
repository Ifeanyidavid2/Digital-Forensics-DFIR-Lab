# Day 14 - Investigation Notes
## 1. Scope and Tooling
- Artifact examined: C:\Windows\Prefetch\CERTUTIL.EXE-28F1E0C1.pf
- Parser: PECmd 2026.5.0 by Eric Zimmerman
- Parsed JSON: analysis\20261015145723_PECmd_Output.json
- Execution timeline CSV: analysis\CERTUTIL-Execution-Timeline.csv
## 2. Prefetch Observations
- Executable name: CERTUTIL.EXE
- Prefetch filename identifier: 28F1E0C1; this is not a cryptographic integrity hash.
- File size reported by PECmd: 27,682 bytes.
- Run count reported by PECmd: 10.
- Last run reported by PECmd: 2026-10-15 14:21:50.
- Seven previous-run fields were exported. Their timestamps fall between 14:21:49 and 14:21:50 on 2026-10-15.
- PECmd reported ParsingError=False.
- The execution timeline CSV was verified to contain eight records: one LastRun and seven PreviousRun records.
## 3. Security Log Corroboration
- The observed Security log range extended from 2026-10-15 12:14:25 (Record ID 2297102) to 2026-10-20 14:02:34 (Record ID 2330628).
- A search for Security Event ID 4688 messages mentioning certutil.exe from 2026-10-15 14:15:00 through 14:30:00 returned no matches.
- A sample Event ID 4688 described lsass.exe with parent wininit.exe; it did not corroborate certutil.exe execution.
- The current Process Creation audit policy was reported as No Auditing and recorded in analysis\Audit-Policy-Observation.csv at 2026-10-20 14:23:15 +01:00.
- The historical audit policy at the time of the Prefetch-reported execution has not been established.
## 4. Assessment and Limitations
- Prefetch supports recorded execution-related activity for CERTUTIL.EXE, but does not by itself identify the user, command-line arguments, purpose, or maliciousness.
- No matching Event ID 4688 was found in the searched time window. This is a corroboration gap, not proof that execution did not occur.
- The current No Auditing setting may help explain limited process-creation evidence, but it cannot establish the historical policy state.
- PECmd's referenced file and directory lists are artifact metadata; they do not independently prove causation or malicious activity.
- Findings should be correlated with other available evidence before drawing conclusions.
## 5. Evidence and Output Files
- analysis\Prefetch-Inventory.csv
- analysis\Prefetch-SHA256-Manifest.csv
- analysis\20261015145723_PECmd_Output.json
- analysis\CERTUTIL-Execution-Timeline.csv
- analysis\Audit-Policy-Observation.csv
## 6. Collection Notes
- The source Prefetch artifact was parsed in place; no forensic image acquisition is documented here.
- Record times above are preserved as reported by the relevant tools or Windows output. Time-zone handling for the parsed Prefetch timestamps has not been independently validated.
