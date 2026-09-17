\# Day 01 — Digital Forensics \& DFIR Fundamentals



\## Overview



This lab introduces the fundamental principles of Digital Forensics and Incident Response (DFIR), including evidence identification, preservation, collection, examination, analysis, timeline reconstruction, and reporting.



The primary objective was to develop an evidence-based investigative mindset and understand why forensic conclusions must be supported by correlated digital evidence rather than assumptions.



\---



\## Learning Objectives



By completing this lab, I developed an understanding of:



\* Digital Forensics and Incident Response (DFIR)

\* The digital forensic investigation lifecycle

\* Digital evidence preservation

\* Volatile and non-volatile evidence

\* Evidence integrity

\* Digital forensic artifacts

\* Indicators of Compromise (IOCs)

\* Evidence correlation

\* Timeline analysis

\* Evidence-based forensic conclusions



\---



\## DFIR Investigation Lifecycle



The investigation process used throughout this lab follows the general workflow:



```text

Incident / Suspicion

&#x20;       ↓

Identification

&#x20;       ↓

Preservation

&#x20;       ↓

Collection

&#x20;       ↓

Examination

&#x20;       ↓

Analysis

&#x20;       ↓

Timeline Reconstruction

&#x20;       ↓

Reporting

&#x20;       ↓

Incident Response / Lessons Learned

```



A key principle is:



> Preserve first. Analyze second.



Investigators should avoid unnecessary actions that could alter or destroy potentially valuable evidence.



\---



\## Investigation Scenario



At 08:30, the Security Operations Center (SOC) reported that Wazuh had generated suspicious PowerShell alerts from an employee's Windows workstation.



The employee reported opening an unexpected Microsoft Word document shortly before the alert.



The workstation remained powered on and connected to the corporate network.



Management requested an investigation to determine whether the workstation had been compromised.



\---



\## Initial Forensic Response



The first action should be to document the current state of the workstation and determine what evidence needs to be preserved in accordance with organizational incident-response and forensic procedures.



Because the workstation is powered on, potentially valuable volatile evidence may exist in memory.



Potential evidence includes:



\* RAM

\* Running processes

\* Active network connections

\* Logged-on users

\* PowerShell activity

\* Windows Event Logs

\* Wazuh alerts

\* Suspicious files

\* Relevant timestamps



Restarting the workstation, deleting suspicious files, or immediately allowing antivirus software to quarantine files could alter or destroy evidence required for further analysis.



\---



\## Volatile Evidence



Immediately shutting down the workstation could destroy evidence stored in volatile memory.



Potential volatile evidence includes:



\* Running malicious processes

\* Active network connections

\* Command-line arguments

\* Runtime artifacts

\* Injected code

\* Decrypted information present in memory

\* Credentials or authentication material present in memory



A live system may therefore contain forensic evidence that will no longer exist after shutdown.



However, containment decisions must consider operational risk and established incident-response procedures, particularly during an active destructive attack.



\---



\## PowerShell Analysis



The presence of `powershell.exe` alone does not prove that the workstation has been compromised.



PowerShell is a legitimate Windows administration and automation tool.



Its significance depends on surrounding context.



Important investigative questions include:



\* Who launched PowerShell?

\* What was its parent process?

\* What command line was executed?

\* Was the command encoded or obfuscated?

\* What network connections occurred afterward?

\* What files were created or modified?

\* What processes subsequently executed?



For example:



```text

WINWORD.EXE

&#x20;   ↓

powershell.exe

&#x20;   ↓

Encoded command

&#x20;   ↓

Suspicious network connection

&#x20;   ↓

update.exe created

&#x20;   ↓

update.exe executed

```



This sequence provides substantially stronger evidence than the presence of `powershell.exe` alone.



\---



\## Evidence Identified



During the scenario, the following artifacts were identified:



```text

Suspicious File:

C:\\Users\\David\\AppData\\Local\\Temp\\update.exe



SHA-256:

5f83c1...



Network Connection:

185.XX.XX.24:443



Observed Process:

powershell.exe

```



These artifacts should be correlated with additional host, memory, network, and log evidence before reaching a final conclusion.



\---



\## Timeline Analysis



The following sequence of events was observed:



```text

09:14:02  Employee opens Invoice.docm

09:14:07  WINWORD.EXE launches powershell.exe

09:14:09  PowerShell executes an encoded command

09:14:12  Connection established to suspicious.example

09:14:16  update.exe written to Temp

09:14:20  update.exe executes

```



\### Analysis



The timeline demonstrates that shortly after `Invoice.docm` was opened, `WINWORD.EXE` launched PowerShell.



PowerShell subsequently executed an encoded command, followed by a connection to a suspicious domain.



A file named `update.exe` was then written to the user's Temp directory and executed.



These correlated events provide strong evidence of suspicious execution associated with the document.



However, further examination of the PowerShell command, `update.exe`, network activity, memory, and other endpoint artifacts would be required to determine the capabilities, persistence, scope, and impact of the activity.



\---



\## Forensic Reasoning



An important lesson from this investigation is that individual artifacts should not automatically be treated as proof of compromise.



For example:



```text

powershell.exe

```



is not sufficient by itself to demonstrate malicious activity.



Instead, the investigator should correlate multiple sources of evidence:



```text

Document

&#x20;  ↓

Parent Process

&#x20;  ↓

PowerShell

&#x20;  ↓

Command Line

&#x20;  ↓

Network Connection

&#x20;  ↓

File Creation

&#x20;  ↓

Process Execution

```



This allows the investigation to move from individual observations toward defensible findings.



\---



\## Key DFIR Principle



The investigation reinforced the following methodology:



```text

Evidence

&#x20;   ↓

Correlation

&#x20;   ↓

Conclusion

```



rather than:



```text

Suspicion

&#x20;   ↓

Assumption

&#x20;   ↓

Conclusion

```



Forensic conclusions should remain within what the available evidence can reasonably support.



\---



\## Lab Structure



```text

Day-01-DFIR-Fundamentals/

│

├── evidence/

├── notes/

├── report/

└── README.md

```



Future evidence, screenshots, notes, and reports related to this lab can be stored within their respective directories.



\---



\## Skills Demonstrated



\* DFIR fundamentals

\* Evidence identification

\* Evidence preservation awareness

\* Volatile evidence awareness

\* Initial incident triage

\* Windows process analysis

\* IOC identification

\* Timeline analysis

\* Evidence correlation

\* Forensic reasoning

\* Technical documentation



\---



\## Conclusion



Day 1 established the foundational mindset required for digital forensic investigations.



The most important lesson is that forensic analysis is not simply about finding suspicious files or processes. It requires preserving evidence, examining context, correlating multiple artifacts, reconstructing events, and ensuring that conclusions are supported by the available evidence.



This evidence-driven approach will form the foundation for subsequent DFIR investigations throughout this lab.



