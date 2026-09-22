# Day 04 — Forensic Imaging & Acquisition



## Overview



Day 04 focuses on forensic acquisition, evidence preservation, forensic imaging, and integrity verification.



The purpose of forensic acquisition is to obtain an examination copy of digital evidence while minimizing unnecessary changes to the source and documenting sufficient information to support the integrity of the acquired data.



This lab used a controlled binary source image to simulate storage media and demonstrate a RAW/DD-style byte-for-byte acquisition.



The exercise also demonstrated how SHA-256 verification can detect a modification even when the source and modified files remain exactly the same size.



## Learning Objectives



The objectives of this lab were to understand and demonstrate:



* Forensic acquisition principles

* Physical versus logical acquisition concepts

* RAW/DD forensic images

* Evidence preservation

* Write-blocking concepts

* Source and acquisition hashing

* SHA-256 verification

* Acquisition integrity

* Verification failures

* Controlled evidence modification

* Forensic documentation

* Limitations of simulated acquisition



## Investigation Scenario



Case ID: `DFIR-2026-002`



Evidence ID: `DFIR-D04-E001`



Incident: Suspected Unauthorized Data Transfer



An employee was suspected of transferring confidential company information to removable storage.



The investigative objective was to preserve the source, create a forensic acquisition, verify the acquired data against the source, and conduct subsequent examination from an appropriate copy rather than unnecessarily modifying the original evidence.



For safety and repeatability, the practical lab used a controlled 16 MiB binary source image instead of an actual seized USB device.



## Ordinary File Copy vs. Forensic Acquisition



Copying visible files from storage media is not equivalent to an appropriate physical forensic acquisition.



An ordinary logical file copy generally operates through the filesystem and may omit potentially relevant evidence such as:



* Deleted-file remnants

* Unallocated space

* Slack space

* Filesystem metadata

* Partition information

* Hidden or system data

* Low-level storage artifacts



A physical forensic acquisition is intended to capture the addressable contents of the source according to the acquisition method being used.



This distinction is important because evidence that is no longer visible through the filesystem may still remain within the storage media.



## Write Blocking



A write blocker is used to prevent the forensic workstation from writing data back to the evidence device while allowing the investigator to read and acquire data from it.



The general principle is:



`Read from the evidence; prevent writes to the evidence whenever appropriate and technically possible.`



Connecting evidence directly to an ordinary workstation can create forensic concerns because the operating system or installed software may interact with the device and potentially modify filesystem or system-related metadata.



This lab did not use a physical evidence device or hardware write blocker.



## Lab Environment



The lab was performed on a Windows workstation using PowerShell and .NET file operations.



The controlled source image was:



`DFIR-D04-E001-source.img`



Source size:



`16,777,216 bytes (16 MiB)`



Two controlled training artifacts were embedded within the binary source image at predetermined offsets.



The source image was then acquired into:



`DFIR-D04-E001-acquired.dd`



The acquisition was performed using a byte-for-byte file-stream copy to simulate a RAW/DD-style acquisition.



## Acquisition Workflow



The lab followed this workflow:



`Identify → Preserve → Acquire → Hash → Verify → Analyze`



The source image was prepared and finalized before acquisition.



A SHA-256 baseline was calculated for the controlled source.



The source was then copied byte-for-byte into a RAW/DD-style acquisition file.



The acquired image was independently hashed and compared with the source SHA-256 value.



## Source Image



Artifact:



`DFIR-D04-E001-source.img`



Type:



Controlled Source Image



Size:



`16,777,216 bytes`



SHA-256:



`E26AABF4A9DB39A4C7579BC0D391CE1D157E0B4A9EC6399678005FB04DBD4B36`



This hash established the baseline against which the acquisition was verified.



## Acquired Image



Artifact:



`DFIR-D04-E001-acquired.dd`



Type:



RAW/DD-style Acquisition



Size:



`16,777,216 bytes`



SHA-256:



`E26AABF4A9DB39A4C7579BC0D391CE1D157E0B4A9EC6399678005FB04DBD4B36`



Verification result:



`MATCH`



The source image and acquired image produced identical SHA-256 values.



This supports that the acquired data was byte-for-byte consistent with the controlled source image at the points represented by the hash verification.



## What Successful Verification Supports



Matching source and acquisition hashes provide important support for acquisition integrity.



In this lab, the matching SHA-256 values support that the compared source and acquired image were identical at the time of verification.



However, matching hashes alone do not establish:



* Who originally created the data

* Who owns the storage device

* Who performed a particular activity

* Whether a file is malicious

* Whether the evidence was altered before acquisition

* Whether every chain-of-custody procedure was performed correctly

* The meaning or evidentiary significance of the acquired content



Hash verification supports integrity between the compared data states; it does not establish attribution or interpretation.



## Controlled Corruption Test



A separate copy of the verified acquisition was created:



`DFIR-D04-E001-corruption-test.dd`



Before modification, its SHA-256 was:



`E26AABF4A9DB39A4C7579BC0D391CE1D157E0B4A9EC6399678005FB04DBD4B36`



Verification before modification:



`MATCH`



A single bit was then intentionally changed in the disposable test copy.



The file size remained:



`16,777,216 bytes`



After the modification, its SHA-256 became:



`AE3BAEB6E642473963A6E93480C2C352C7C0B5C6BB79E5FE770E9916E2EAD4CF`



Verification after modification:



`MISMATCH`



This demonstrates that equal file size does not establish identical content.



A very small change to the data resulted in a completely different SHA-256 digest and was detected during verification.



## Verification Failure



If forensic acquisition software reports a verification failure, the image should not automatically be treated as successfully verified.



The investigator should:



* Preserve the acquisition and verification logs

* Document the discrepancy

* Confirm that the correct source and image were compared

* Confirm the correct hash algorithm

* Review acquisition settings and tool errors

* Determine whether the source changed during acquisition

* Consider reacquisition using validated procedures where appropriate

* Escalate unexplained integrity discrepancies according to procedure



A hash mismatch demonstrates that the compared data states do not match as expected.



It does not, by itself, prove malicious tampering.



## Filesystem Repair Risk



A seized storage device should not casually be subjected to operating-system repair operations such as:



`Scan and fix`



Such an operation may write changes to the original evidence, including filesystem structures or metadata.



The forensic approach is to document the condition of the evidence, protect it from unnecessary writes, acquire it using an appropriate procedure, and conduct examination from an appropriate forensic copy.



## Acquisition Verification Results



| Artifact                         |             Size | SHA-256 Result      | Verification |

| -------------------------------- | ---------------: | ------------------- | ------------ |

| DFIR-D04-E001-source.img         | 16,777,216 bytes | E26AABF4...DBD4B36  | Baseline     |

| DFIR-D04-E001-acquired.dd        | 16,777,216 bytes | E26AABF4...DBD4B36  | MATCH        |

| DFIR-D04-E001-corruption-test.dd | 16,777,216 bytes | AE3BAEB6...E2EAD4CF | MISMATCH     |



The complete SHA-256 values are retained in the acquisition verification record.



## Lab Artifacts



The Day 04 lab contains:



`acquisition/Acquisition-Verification-Record.csv`



This records the source, verified acquisition, controlled corruption test, SHA-256 values, file sizes, and verification results.



`acquisition/Acquisition-Notes.txt`



This documents the acquisition method, hashes, results, limitations, and forensic principles applied during the exercise.



Generated forensic image files are excluded from Git tracking to avoid unnecessarily storing large binary lab artifacts in the repository.



## Lab Limitations



This exercise was a controlled acquisition simulation.



It did not involve:



* A physically seized USB device

* Hardware write-blocking equipment

* FTK Imager

* EnCase

* `ewfacquire`

* An E01 evidence container

* A real-world chain-of-custody transfer



The source was a controlled binary image created specifically for training.



The acquisition was performed using .NET file streams to demonstrate byte-for-byte acquisition and verification concepts.



Therefore, this lab should be described as a controlled RAW/DD-style forensic acquisition simulation rather than a physical-device forensic acquisition.



## Skills Demonstrated



* Forensic imaging concepts

* Physical versus logical acquisition reasoning

* RAW/DD acquisition concepts

* Evidence preservation

* Write-blocking awareness

* SHA-256 hashing

* Source-to-image verification

* Integrity verification

* Verification failure analysis

* Controlled corruption testing

* Evidence documentation

* Forensic reasoning

* PowerShell

* .NET file-stream operations



## Key Principle



The central forensic principle demonstrated in this lab is:



`Preserve → Acquire → Hash → Verify → Analyze`



The original evidence should be protected from unnecessary alteration, and analysis should normally be performed against an appropriate verified forensic copy.



## Conclusion



Day 04 demonstrated the importance of forensic acquisition and integrity verification.



A controlled 16 MiB source image was acquired into a RAW/DD-style forensic image. Both source and acquisition produced the same SHA-256 value, supporting successful acquisition integrity.



A separate controlled copy was then modified by a single bit. Although its file size remained unchanged, its SHA-256 digest changed and verification failed.



The exercise demonstrates why forensic investigators rely on documented acquisition procedures, evidence preservation, cryptographic hashing, and verification rather than ordinary file copying or file-size comparison alone.




