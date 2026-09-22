# Day 03 — Hashing and Evidence Integrity



## Overview



This lab demonstrates the use of cryptographic hashing to verify the integrity of digital forensic evidence.



A controlled evidence file was created and hashed using SHA-256. A working copy was then produced and independently hashed to verify that its contents matched the original evidence.



The working copy was subsequently modified to demonstrate how a change to file contents results in a different SHA-256 digest.



The exercise reinforces a fundamental digital forensics principle:



> Hashing supports evidence integrity verification by allowing investigators to determine whether the data being examined matches the data represented by a previously recorded hash.



\---



## Learning Objectives



The objectives of this lab were to:



* Understand the role of cryptographic hashing in digital forensics.

* Calculate SHA-256 hashes using PowerShell.

* Establish a baseline hash for digital evidence.

* Verify a forensic working copy against the original evidence.

* Observe the effect of modifying file contents.

* Understand the SHA-256 avalanche effect.

* Distinguish evidence integrity from malware determination or attribution.

* Understand why original evidence should be preserved.

* Document hash verification results in a structured forensic record.



\---



## Lab Environment



**Platform:** Windows

**Shell:** PowerShell

**Repository:** Digital-Forensics-DFIR-Lab

**Case ID:** DFIR-2026-001

**Evidence ID:** DFIR-D03-E001

**Hash Algorithm:** SHA-256



\---



## Evidence Structure



The lab used the following directory structure:



```text

Day-03-Hashing-Evidence-Integrity/

│

├── evidence/

│   ├── original/

│   │   └── suspicious-activity.txt

│   ├── working-copy/

│   │   └── suspicious-activity-working.txt

│   └── Hash-Verification-Record.csv

│

├── notes/

├── report/

└── README.md

```



\---



## Original Evidence



The controlled evidence sample contained:



```text

DFIR TRAINING EVIDENCE

Case: DFIR-2026-001

Evidence ID: DFIR-D03-E001

Artifact: Simulated suspicious PowerShell activity

Status: Training Sample

```



The file was stored as:



```text

evidence/original/suspicious-activity.txt

```



\---



## Establishing the Baseline Hash



The original evidence was hashed using SHA-256 with PowerShell:



```powershell

Get-FileHash `

.\\evidence\\original\\suspicious-activity.txt `

\-Algorithm SHA256

```



The resulting SHA-256 was:



```text

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830

```



This value became the baseline integrity value for the evidence.



\---



## Creating the Working Copy



A working copy was created from the original evidence:



```powershell

Copy-Item `

.\\evidence\\original\\suspicious-activity.txt `

.\\evidence\\working-copy\\suspicious-activity-working.txt

```



The working copy was then independently hashed.



### Working Copy SHA-256



```text

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830

```



Comparison:



```text

Original:

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830



Working Copy:

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830



Verification Result:

MATCH

```



The PowerShell comparison returned:



```text

True

```



This demonstrated that the original and working copy contained identical data at the time of verification.



The fact that the files had different filenames did not affect their SHA-256 values because the file-content hashing operation was performed against the file contents rather than the filenames.



\---



## Controlled Modification



The working copy was deliberately modified by adding:



```text

Additional investigation note.

```



The original evidence was not modified.



After modification, the working copy was hashed again.



### Modified Working Copy SHA-256



```text

447E6EA47FB81B242BE834A9EE0E782FC0A24DF77432994B6C527140C869948E

```



Comparison with the original:



```text

Original:

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830



Modified Working Copy:

447E6EA47FB81B242BE834A9EE0E782FC0A24DF77432994B6C527140C869948E

```



Verification result:



```text

MISMATCH

```



PowerShell returned:



```text

False

```



The modification therefore caused the working copy to fail integrity verification against the original baseline.



\---



## Hash Verification Results



| Evidence State                   | SHA-256                                                            | Verification |
| -------------------------------- | ------------------------------------------------------------------ | ------------ |
| Original evidence                | `E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830` | Baseline     |
| Working copy before modification | `E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830` | MATCH        |
| Working copy after modification  | `447E6EA47FB81B242BE834A9EE0E782FC0A24DF77432994B6C527140C869948E` | MISMATCH     |



The results were documented in:



```text

evidence/Hash-Verification-Record.csv

```



\---



## SHA-256 Avalanche Effect



SHA-256 exhibits a cryptographic property known as the **avalanche effect**.



A small change to the input data can produce a substantially different 256-bit hash output.



In this experiment, adding only one line changed the SHA-256 from:



```text

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830

```



to:



```text

447E6EA47FB81B242BE834A9EE0E782FC0A24DF77432994B6C527140C869948E

```



This does not mean the entire file was rewritten. It demonstrates that the data being hashed was no longer identical to the original data.



\---



## Handling a Hash Mismatch



If forensic evidence has a documented hash but a newly calculated hash does not match, the discrepancy should not be ignored.



An appropriate response includes:



1\. Recalculate the hash to rule out an error.

2\. Confirm that the correct evidence was selected.

3\. Confirm that the correct hashing algorithm was used.

4\. Review acquisition documentation.

5\. Review chain-of-custody records.

6\. Determine whether the evidence underwent an authorized transformation or processing step.

7\. Locate an authoritative original or verified forensic copy where available.

8\. Document the discrepancy.

9\. Escalate according to forensic procedures before representing the evidence as integrity-verified.



A hash mismatch demonstrates an **integrity discrepancy requiring investigation**.



It does not, by itself, prove malicious tampering.



\---



## Integrity Does Not Mean Safety



A matching hash does not establish that a file is safe or non-malicious.



For example:



```text

Acquired update.exe

&#x20;       ↓

&#x20;    ABC123...



Working copy

&#x20;       ↓

&#x20;    ABC123...

```



A match demonstrates that the compared contents are identical to the data represented by the recorded hash.



It does not determine whether the file is malware.



Maliciousness would require additional analysis, potentially including:



* Static analysis

* Behavioral analysis

* Execution context

* Network activity

* Persistence mechanisms

* Threat intelligence or reputation information

* Correlation with other forensic evidence



Therefore:



```text

Matching hash ≠ safe file

Matching hash = matching content

```



\---



## Preservation of Original Evidence



Original evidence should be appropriately preserved because forensic investigations should be repeatable, auditable, and defensible.



Casually analyzing or modifying original evidence may alter:



* File contents

* Metadata

* Timestamps

* Filesystem structures

* Logs

* Other forensic artifacts



A preferred workflow is:



```text

Original Evidence

&#x20;       ↓

Appropriate Acquisition

&#x20;       ↓

Calculate and Document Hash

&#x20;       ↓

Preserve Evidence

&#x20;       ↓

Create Appropriate Forensic/Working Copy

&#x20;       ↓

Verify Integrity

&#x20;       ↓

Perform Analysis

&#x20;       ↓

Document Analyst Actions

```



If a working copy becomes corrupted or altered, another appropriate copy can be produced from the preserved evidence.



Preservation also supports independent examination and reproduction of findings where appropriate.



\---



## Final Integrity Verification



At the end of the experiment, the original evidence was hashed again.



Final SHA-256:



```text

E8C7C05230CDD68C0DDDBAFD5D7FF8EEF7D3205375A5486D79A22BE7516FB830

```



This matched the original baseline hash.



Therefore, the controlled modification affected the working copy while the original evidence remained unchanged.



\---



## Key Forensic Principle



The central lesson from this exercise is:



> **Hashing does not determine whether evidence is good, bad, safe, or malicious. It provides a mechanism for checking whether the data being examined is identical to the data represented by a previously recorded hash.**



Forensic conclusions should therefore follow:



```text

Preserve

&#x20;  ↓

Acquire

&#x20;  ↓

Hash

&#x20;  ↓

Verify

&#x20;  ↓

Analyze

&#x20;  ↓

Correlate

&#x20;  ↓

Document

```



\---



## Skills Demonstrated



This lab demonstrates practical experience with:



* Digital evidence integrity

* SHA-256 hashing

* PowerShell `Get-FileHash`

* Evidence preservation

* Working-copy verification

* Hash mismatch detection

* Cryptographic avalanche effect

* Forensic documentation

* Evidence-integrity reasoning

* Reproducible forensic methodology



\---



## Conclusion



The Day 03 lab successfully demonstrated how SHA-256 hashing can be used to establish and verify the integrity of digital forensic evidence.



The original evidence and initial working copy produced identical SHA-256 values, demonstrating matching content. After the working copy was deliberately modified, its SHA-256 changed significantly and no longer matched the baseline.



A final verification confirmed that the original evidence retained its initial SHA-256 value.



The exercise demonstrates why cryptographic hashing, preservation of original evidence, verified working copies, and accurate documentation are fundamental components of a defensible digital forensic investigation.




