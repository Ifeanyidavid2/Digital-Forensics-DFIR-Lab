\# Day 02 — Digital Evidence \& Chain of Custody



\## Overview



This lab focuses on identifying, preserving, documenting, and tracking digital evidence during a Digital Forensics and Incident Response (DFIR) investigation.



The investigation continues from the suspected Windows workstation compromise introduced during Day 01.



The primary focus is maintaining evidence integrity and establishing an auditable chain of custody.



\---



\## Learning Objectives



This lab developed practical understanding of:



\* Digital evidence identification

\* Volatile and non-volatile evidence

\* Order of volatility

\* Evidence preservation

\* Forensic acquisition

\* Evidence integrity

\* Cryptographic hashing concepts

\* Evidence registers

\* Chain of custody

\* Evidence transfer documentation

\* Risk-based evidence acquisition



\---



\## Investigation Scenario



A Windows workstation remained powered on following suspicious PowerShell activity detected by Wazuh.



Potential evidence included:



\* Running processes

\* RAM

\* Active network connection to `185.XX.XX.24:443`

\* Windows Event Logs

\* `update.exe`

\* Employee 512 GB SSD

\* Wazuh alerts

\* `Invoice.docm`

\* Connected USB storage device



The investigation required determining how this evidence should be classified, prioritized, preserved, and documented.



\---



\## Volatile Evidence



The following evidence was classified primarily as volatile:



\* Running processes

\* RAM

\* Active network connections



These artifacts can change or disappear as normal system activity continues or when the workstation loses power.



RAM was considered particularly important because it may contain process memory, command-line information, injected code, network-related artifacts, decrypted content, and other runtime evidence.



\---



\## Non-Volatile Evidence



The following evidence was classified primarily as non-volatile:



\* Windows Event Logs

\* `update.exe`

\* Employee SSD

\* Wazuh alerts already stored by the SIEM

\* `Invoice.docm`

\* USB storage contents



Non-volatile does not mean immutable.



Persistent evidence can still be modified, deleted, cleared, or overwritten.



\---



\## Order of Volatility



A major investigative principle demonstrated during this lab was that evidence likely to disappear first may require earlier collection.



For this scenario, the approximate priority was:



```text

Document system state

&#x20;       ↓

Capture RAM / volatile evidence

&#x20;       ↓

Preserve live-state information

&#x20;       ↓

Acquire persistent storage

&#x20;       ↓

Hash and verify acquisitions

&#x20;       ↓

Preserve originals

&#x20;       ↓

Analyze working copies

```



This sequence is not absolute.



If the live workstation presents an immediate operational threat, containment requirements may override the preferred forensic acquisition order.



\---



\## Evidence Handling



Executing a suspicious file such as `update.exe` directly from an investigator's workstation would be poor forensic practice.



Potential consequences include:



\* Activating malware

\* Creating new network connections

\* Modifying files

\* Creating registry entries

\* Establishing persistence

\* Generating new logs

\* Altering timestamps

\* Contaminating the investigation environment

\* Potentially compromising additional systems



A safer forensic workflow is:



```text

Preserve

&#x20;  ↓

Acquire

&#x20;  ↓

Hash

&#x20;  ↓

Verify

&#x20;  ↓

Analyze Working Copy

```



Suspicious executable analysis should be conducted using an appropriately controlled and isolated environment.



\---



\## Evidence Register



An Evidence Register was created to provide a structured inventory of identified evidence.



Evidence identifiers were assigned using the format:



```text

DFIR-D02-E001

DFIR-D02-E002

DFIR-D02-E003

...

```



Seven evidence records were documented.



The register contains information including:



\* Evidence ID

\* Case ID

\* Description

\* Evidence type

\* Source

\* Volatility

\* Collector

\* Collection time

\* Acquisition method

\* SHA-256 status

\* Evidence status

\* Notes



Unknown values were recorded as `PENDING` rather than fabricated.



\---



\## Chain of Custody



A Chain of Custody record was created for:



```text

Evidence ID: DFIR-D02-E001

```



The custody history records:



```text

11:20

Evidence collected

&#x20;     ↓

Ifeanyi David Ezechukwukere

&#x20;     ↓

13:45

Evidence transferred

&#x20;     ↓

Analyst B

&#x20;     ↓

Forensic examination

```



Each transfer should create an additional custody record rather than replacing previous entries.



This creates a continuous and auditable history:



```text

Collected

&#x20;   ↓

Stored

&#x20;   ↓

Transferred

&#x20;   ↓

Examined

&#x20;   ↓

Returned / Stored

```



\---



\## Hash Integrity Principle



Matching cryptographic hashes provide strong evidence that the hashed data has not changed between verification points.



For example:



```text

Acquisition SHA-256

A94F21C8...

&#x20;      =

Verification SHA-256

A94F21C8...

```



A matching hash supports evidence integrity.



However, it does not independently establish:



\* Who created the original data

\* Who performed an activity

\* Whether a suspicious file is malware

\* Whether the workstation was compromised

\* When an activity occurred

\* Whether every evidence-handling procedure was performed correctly



Therefore:



> Hash integrity supports evidence integrity; it does not establish the meaning or attribution of the evidence.



\---



\## Evidence Acquisition Decision



Given the scenario, RAM was prioritized before SSD acquisition.



The reasoning was:



1\. The workstation remained powered on.

2\. Suspicious PowerShell activity had been observed.

3\. An active suspicious network connection had been identified.

4\. RAM contained potentially valuable volatile evidence.

5\. The SSD contained persistent evidence that could generally be acquired afterward.



This decision assumed that the workstation was stable and no immediately destructive activity was occurring.



If active ransomware, destructive malware, or ongoing attacks against other systems were identified, containment requirements could change the acquisition priority.



\---



\## Lab Artifacts



```text

Day-02-Evidence-Chain-of-Custody/

│

├── evidence/

│   ├── Evidence-Register.csv

│   └── Chain-of-Custody.csv

│

├── notes/

├── report/

└── README.md

```



\---



\## Skills Demonstrated



\* Digital evidence classification

\* Volatile evidence identification

\* Order-of-volatility reasoning

\* Evidence preservation

\* Evidence register creation

\* Chain-of-custody documentation

\* Evidence transfer tracking

\* Integrity verification concepts

\* Risk-based forensic decision-making

\* Professional DFIR documentation



\---



\## Key Lesson



Digital forensics is not simply about obtaining data.



Evidence must be:



```text

Identified

&#x20;   ↓

Preserved

&#x20;   ↓

Documented

&#x20;   ↓

Acquired

&#x20;   ↓

Integrity Verified

&#x20;   ↓

Analyzed

&#x20;   ↓

Reported

```



The investigator must be able to explain where evidence originated, how it was collected, who handled it, whether its integrity was maintained, and how it supports the final findings.



\---



\## Conclusion



Day 02 established the evidence-management foundation required for defensible digital forensic investigations.



The lab demonstrated that evidence integrity depends not only on technical analysis but also on preservation, documentation, acquisition methodology, cryptographic verification, and continuous chain-of-custody records.



