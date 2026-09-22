# Day 05 — File Systems & Forensic Artifacts



## Overview



This lab explores Windows NTFS filesystem artifacts and demonstrates how multiple evidence sources can be normalized, correlated, and interpreted during a digital forensic investigation.



The exercise uses a controlled simulated evidence set rather than artifacts extracted from a live production system.



The investigation focuses on a confidential spreadsheet that was reportedly removed from a Windows workstation and demonstrates the distinction between filesystem observations, timeline correlation, investigative hypotheses, and human attribution.



## Learning Objectives



The objectives of this lab were to:



* Understand the forensic significance of NTFS filesystem structures.

* Explain the role of the NTFS Master File Table (`$MFT`).

* Understand the forensic value of the NTFS Update Sequence Number Journal (`$UsnJrnl`).

* Distinguish allocated space, unallocated space, and file slack.

* Understand why file deletion does not necessarily immediately destroy underlying data.

* Correlate filesystem, USB, and Windows logon artifacts.

* Build a normalized forensic timeline using PowerShell.

* Separate direct observations from investigative inference.

* Avoid unsupported human attribution.

* Document findings in a repeatable and defensible manner.



## Investigation Scenario



**Case ID:** `DFIR-2026-003`



**Incident:** Suspected Confidential File Removal



A confidential spreadsheet named:



`Board-Financial-Plan-2027.xlsx`



was reportedly associated with:



`C:\Users\David\Documents\`



The file was no longer visible through the normal filesystem view.



The simulated investigation identified evidence associated with:



* An authenticated Windows session.

* A connected USB device.

* An NTFS `$MFT` record associated with the spreadsheet.

* NTFS `$UsnJrnl` activity associated with the same filename.



The objective was to determine what the artifacts establish while avoiding unsupported conclusions about who performed the activity.



## NTFS Forensic Concepts



### Master File Table — `$MFT`



The NTFS Master File Table contains records describing files and directories on an NTFS volume.



An MFT record can provide information such as:



* Filename information.

* File size.

* Timestamps.

* File attributes.

* Parent-directory information.

* Allocation information.

* References to file data.

* Whether a record is currently allocated or marked deleted.



An MFT record associated with a deleted file can therefore provide useful forensic evidence even when the file is no longer visible through normal filesystem browsing.



However, an MFT record does not automatically establish which human being created, opened, copied, modified, or deleted a file.



### Update Sequence Number Journal — `$UsnJrnl`



The NTFS Update Sequence Number Journal can record information associated with changes to files and directories.



Depending on the available records, it can assist an examiner in reconstructing filesystem activity involving events such as file creation, modification, renaming, or deletion.



Like the `$MFT`, `$UsnJrnl` evidence requires contextual interpretation and correlation with other evidence sources.



## Allocated, Unallocated, and Slack Space



### Allocated Space



Allocated space is storage currently assigned to active files or filesystem structures.



It normally contains data belonging to files currently recognized by the filesystem.



### Unallocated Space



Unallocated space is storage the filesystem currently considers available for reuse.



It may contain residual data belonging to previously deleted files until those locations are reused, overwritten, or otherwise affected by storage behavior.



### File Slack



File slack refers to unused space associated with the storage allocated to a file, particularly space between the logical end of file data and the end of the relevant allocated storage unit.



Depending on the filesystem and storage circumstances, slack can potentially contain residual information.



## File Deletion and Data Persistence



Deleting a file does not necessarily mean that all evidence associated with it immediately disappears.



A filesystem may mark the relevant record or storage locations as available for reuse while some underlying content or metadata remains.



This is different from overwriting.



**Deletion** changes filesystem state and makes storage available for reuse.



**Overwriting** replaces previous data in storage locations with new data.



Deleted-data recovery can also be affected by storage technologies such as SSD TRIM and garbage collection. Therefore, an investigator should not assume that deleted data will always remain recoverable.



## Simulated Evidence Set



Four controlled artifacts were created for the investigation.



| Evidence ID   | Artifact       | Source               | Forensic Value                                                  |

| ------------- | -------------- | -------------------- | --------------------------------------------------------------- |

| DFIR-D05-E001 | MFT Record     | NTFS `$MFT`          | Filesystem metadata associated with deleted spreadsheet         |

| DFIR-D05-E002 | USN Activity   | NTFS `$UsnJrnl`      | Filesystem change activity associated with spreadsheet filename |

| DFIR-D05-E003 | USB Activity   | USB Artifact         | Records simulated USB connection                                |

| DFIR-D05-E004 | Logon Activity | Windows Security Log | Records authenticated user-session context                      |



These artifacts are simulated training evidence and should not be represented as artifacts extracted from an actual production workstation.



## Timeline Construction



The individual CSV artifacts were imported into PowerShell and normalized into a common structure containing:



* Timestamp.

* Evidence ID.

* Evidence source.

* Event description.

* Subject.



The normalized events were then sorted chronologically and exported to:



`analysis/Filesystem-Timeline.csv`



## Correlated Timeline



| Time  | Evidence ID   | Source               | Observation                                              |

| ----- | ------------- | -------------------- | -------------------------------------------------------- |

| 10:10 | DFIR-D05-E004 | Windows Security Log | David's authenticated session was active                 |

| 10:12 | DFIR-D05-E003 | USB Artifact         | Training USB Device connected                            |

| 10:14 | DFIR-D05-E001 | `$MFT`               | Spreadsheet record marked deleted                        |

| 10:15 | DFIR-D05-E002 | `$UsnJrnl`           | Filesystem activity associated with spreadsheet filename |



The events occur within a five-minute period and provide useful temporal correlation.



## Observation



The simulated evidence directly establishes that:



1\. An authenticated session associated with David was active at 10:10.

2\. A simulated USB device connection was recorded at 10:12.

3\. An MFT record associated with `Board-Financial-Plan-2027.xlsx` was marked deleted at 10:14.

4\. USN activity associated with the same filename was recorded at 10:15.



These are observations derived from the controlled evidence set.



## Correlation



The authenticated session was active before the USB connection and filesystem activity.



The USB connection occurred approximately two minutes before the MFT event.



USN activity associated with the spreadsheet filename followed approximately one minute after the MFT event.



The close timing makes the events relevant to one another for investigative purposes, but temporal proximity alone does not establish causation.



## Investigative Hypothesis



The timeline is consistent with activity involving `Board-Financial-Plan-2027.xlsx` occurring shortly after a USB device was connected while David's authenticated session was active.



This supports further investigation into whether the spreadsheet was accessed, transferred, copied, or deleted during the relevant period.



The present evidence does not independently establish that the USB device was used to copy the spreadsheet.



## Attribution Assessment



The available evidence does not establish that David personally:



* Connected the USB device.

* Copied the spreadsheet.

* Deleted the spreadsheet.



An authenticated session establishes account or session context. It does not by itself establish the identity of the person physically or remotely responsible for an action.



Alternative explanations could include:



* Another person using the authenticated session.

* Automated software.

* A script or scheduled process.

* Malware.

* Remote activity.



Additional independent evidence would be required for stronger attribution.



## Additional Evidence for Investigation



Evidence that could strengthen or challenge the hypothesis includes:



* Detailed `$UsnJrnl` reason codes and timestamps.

* NTFS `$LogFile` records.

* USB device history and identifiers.

* Windows Registry artifacts.

* Shell and user-activity artifacts.

* Application activity.

* PowerShell or command history where applicable.

* Process execution evidence.

* File-access evidence.

* EDR or Wazuh telemetry.

* Additional timeline sources.



The objective would be to determine whether independent evidence sources converge on the same explanation.



## Recovered Data and Evidentiary Caution



Finding spreadsheet-like fragments in unallocated space would not automatically prove that those fragments came from `Board-Financial-Plan-2027.xlsx`.



A defensible finding would distinguish:



**Observation:** Financial spreadsheet fragments were recovered from unallocated space.



**Hypothesis:** The fragments may relate to the deleted Board Financial Plan.



**Unestablished claim:** The fragments definitely originated from `Board-Financial-Plan-2027.xlsx`.



This distinction prevents the forensic report from overstating what the evidence actually demonstrates.



## Lab Artifacts



The lab contains the following analysis artifacts:



`analysis/Artifact-Register.csv`



Documents the evidence identifiers, artifact types, sources, and forensic value.



`analysis/Filesystem-Timeline.csv`



Contains the normalized chronological timeline constructed from the four simulated evidence sources.



`analysis/Forensic-Analysis.txt`



Documents observations, correlation, investigative hypothesis, attribution limitations, and conclusion.



The simulated source artifacts are stored under:



`evidence/artifacts/`



## Lab Limitations



This exercise is a controlled forensic simulation.



The following limitations apply:



* No production workstation was examined.

* No real `$MFT` was acquired or parsed.

* No real `$UsnJrnl` was acquired or parsed.

* No physical USB device was examined.

* No actual deleted spreadsheet was recovered.

* No real user activity is being attributed to an individual.

* The timestamps and events were intentionally created for training.

* The lab demonstrates forensic reasoning and artifact correlation rather than full filesystem acquisition and parsing.



## Skills Demonstrated



This lab demonstrates practical understanding of:



* NTFS forensic concepts.

* `$MFT` forensic interpretation.

* `$UsnJrnl` forensic interpretation.

* Allocated and unallocated storage.

* File slack.

* Deleted-file concepts.

* Filesystem timeline analysis.

* Evidence normalization.

* PowerShell-based artifact correlation.

* Evidence traceability.

* Investigative hypothesis development.

* Attribution limitations.

* Defensible forensic reporting.



## Key Investigative Principle



A useful forensic reasoning model is:



**Observation → Correlation → Hypothesis → Attribution**



Each stage requires stronger evidentiary support than the previous stage.



A timeline may demonstrate what occurred on a system more readily than it can establish who physically caused the activity.



## Conclusion



The Day 05 investigation demonstrates how filesystem and supporting artifacts can be combined to reconstruct a sequence of potentially relevant activity.



The simulated evidence establishes temporal correlation between an authenticated session, a USB connection, an MFT record associated with a deleted spreadsheet, and related USN activity.



The evidence supports further investigation into possible file activity or removal but does not establish that David personally performed the actions or that the USB device caused the spreadsheet's disappearance.



The lab reinforces a fundamental DFIR principle:



**Report what the evidence demonstrates, distinguish inference from fact, and do not attribute actions beyond the strength of the available evidence.**




