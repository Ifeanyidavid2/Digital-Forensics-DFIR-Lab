# Day 06 — Deleted File Recovery & File Carving



## Overview



Day 06 focuses on deleted-file recovery, signature-based file carving, recovered-artifact validation, and defensible forensic interpretation.



The laboratory demonstrates how data can be identified and recovered from a controlled raw binary evidence image without relying on original filenames. It also demonstrates why complete recovery, partial recovery, file identification, correlation, and attribution must be treated as separate forensic conclusions.



## Case Information



**Case ID:** DFIR-2026-004

**Topic:** Deleted File Recovery & File Carving

**Environment:** Controlled DFIR Training Lab

**Evidence Image:** `DFIR-D06-EVIDENCE.img`



## Learning Objectives



The objectives of this laboratory were to:



* Understand filesystem-based deleted-file recovery and file carving.

* Identify artifacts using file signatures rather than filename extensions alone.

* Search a raw evidence image for recognizable byte patterns.

* Recover complete artifacts using header/footer carving.

* Examine the limitations of partial recovery.

* Calculate SHA-256 hashes for recovered artifacts.

* Compare recovered artifacts against known source data.

* Distinguish complete-file identity from partial-byte-sequence identity.

* Verify evidence-image integrity before and after analysis.

* Apply cautious forensic language when attribution cannot be established.



## Deleted File Recovery



Deleting a file does not necessarily immediately overwrite all of its underlying data.



Depending on the filesystem, storage technology, subsequent activity, and other factors, portions of a deleted file may remain recoverable.



Recovery possibilities can be affected by:



* filesystem metadata;

* cluster reuse;

* overwriting;

* fragmentation;

* SSD TRIM and garbage collection;

* filesystem behavior; and

* the time and activity occurring after deletion.



Deletion and overwriting should therefore not be treated as equivalent events.



## Filesystem-Based Recovery



Filesystem-based recovery attempts to use remaining filesystem metadata to reconstruct a deleted file.



On NTFS, relevant metadata may include information from structures such as the `$MFT`.



Depending on what remains available, filesystem-based recovery may preserve contextual information including:



* filename;

* path;

* file size;

* timestamps;

* allocation information; and

* data-location information.



This context can make filesystem-based recovery more informative than recovery based solely on raw content.



## File Carving



File carving attempts to identify and recover data based primarily on recognizable content structures or signatures.



It can be useful when filesystem metadata is unavailable, damaged, or insufficient.



Examples of common signatures include:



| Format | Signature                 |
| ------ | ------------------------- |
| PDF    | `25 50 44 46`             |
| JPEG   | `FF D8 FF`                |
| PNG    | `89 50 4E 47 0D 0A 1A 0A` |
| ZIP    | `50 4B 03 04`             |



Modern Microsoft Office formats such as `.docx`, `.xlsx`, and `.pptx` use ZIP-based container structures. A ZIP signature alone, however, does not establish that recovered data is a valid Microsoft Office document.



## Controlled Evidence Image



A controlled 8 MiB binary evidence image was created for this laboratory.



**Image:** `DFIR-D06-EVIDENCE.img`

**Size:** `8,388,608 bytes`



Baseline SHA-256:



`43897BD263327B8BCD00404E4228A58BB0399F7B7A93F3FBB0C0A4C24ADB08EC`



Three controlled training artifacts were embedded at known locations during image construction.



The subsequent carving process searched the image for signatures rather than relying on the original source filenames.



## Signature Discovery



Analysis identified the following signatures:



| Offset     | Signature     | Interpretation |
| ---------- | ------------- | -------------- |
| `0x100000` | `25 50 44 46` | PDF-like data  |
| `0x300000` | `25 50 44 46` | PDF-like data  |
| `0x500000` | `50 4B 03 04` | ZIP-style data |



The signatures were discovered by searching the raw evidence-image bytes.



## Recovery Result 1 — Complete PDF-Like Artifact



A `%PDF` signature was identified at:



`0x100000`



Header/footer carving recovered:



`carved\_pdf\_001.pdf`



Recovered size:



`201 bytes`



SHA-256:



`912C3E56D35A6360B995A6CB4885796B91AFD5E57C4F0F0149F23F6D534518C8`



The hash matched the known controlled source:



`Executive-Budget.pdf`



Within this controlled laboratory dataset, the recovered bytes are therefore bit-for-bit identical to the known source artifact.



## Recovery Result 2 — Extension Versus Content



A second `%PDF` signature was identified at:



`0x300000`



The recovered artifact was:



`carved\_pdf\_002.pdf`



Recovered size:



`197 bytes`



SHA-256:



`3C7EF764277C7663EB4F3BE86FBD288060782DE4228453080D6C696C1688F78E`



This hash matched the controlled source artifact named:



`recovered\_001.jpg`



Although the source used a `.jpg` extension, its underlying content began with:



`25 50 44 46`



which represents `%PDF`.



This demonstrates that filename extensions should not be treated as authoritative evidence of file type.



File signatures, internal structure, metadata, and content should also be examined.



## Recovery Result 3 — Partial ZIP-Style Fragment



A ZIP-style signature was identified at:



`0x500000`



Signature:



`50 4B 03 04`



A conservative 64-byte fragment was recovered as:



`carved\_office\_fragment\_001.bin`



Recovered SHA-256:



`8F67B227E826BC4CA57938694C11FC4F714B97FA7B6431860B6C84A881D9C337`



The complete known training artifact was 92 bytes and had SHA-256:



`C0CC7D4E6CEA19AB209A4EF17E3D11463FB187EFFA1529DD0B5268F0EFF91C54`



The hashes do not match because the complete source and recovered fragment contain different numbers of bytes.



The recovered 64-byte fragment was then compared with the first 64 bytes of the known source.



Both produced:



`8F67B227E826BC4CA57938694C11FC4F714B97FA7B6431860B6C84A881D9C337`



This establishes that the recovered fragment is bit-for-bit identical to the first 64 bytes of the known training artifact.



It does not establish that a complete Microsoft Excel workbook was recovered.



## Complete Versus Partial Recovery



This laboratory demonstrates an important distinction:



**Complete artifact**



A complete recovered artifact may be compared directly with a known complete source using cryptographic hashes.



**Partial artifact**



A partial artifact should not be expected to produce the same full-file hash as the complete source.



A hash mismatch between different-length byte sequences does not by itself establish corruption or tampering.



The examiner must first determine exactly what data is being compared.



## Fragmentation



File carving can become unreliable when files are fragmented.



A file may physically exist as:



`Fragment A → unrelated data → Fragment B → unrelated data → Fragment C`



A basic carving technique may identify the beginning of the file but fail to locate all subsequent fragments correctly.



The result may be:



* incomplete;

* corrupted;

* contaminated with unrelated data; or

* impossible to reconstruct reliably.



Recovered fragments should therefore be reported according to what was actually recovered rather than being presented as complete files.



## Recovery and Attribution



Recovery does not automatically establish original filename, ownership, source, user activity, or who deleted the data.



A defensible investigation separates:



`Artifact Found → Artifact Identified → Artifact Correlated → Artifact Attributed`



Attribution may require additional evidence including:



* filesystem metadata;

* cryptographic hashes;

* file size;

* timestamps;

* cluster or storage relationships;

* embedded metadata;

* application artifacts;

* user activity;

* logs; and

* other independent corroborating evidence.



## Evidence Integrity



The evidence-image SHA-256 was recalculated after analysis.



**Baseline SHA-256:**



`43897BD263327B8BCD00404E4228A58BB0399F7B7A93F3FBB0C0A4C24ADB08EC`



**Post-analysis SHA-256:**



`43897BD263327B8BCD00404E4228A58BB0399F7B7A93F3FBB0C0A4C24ADB08EC`



**Result:** `MATCH`



The matching hashes support that the controlled evidence image remained bit-for-bit unchanged during the measured analysis interval.



## Laboratory Artifacts



### Analysis



`analysis/Recovery-Verification-Record.csv`



Records recovered artifacts, offsets, signatures, lengths, hashes, recovery status, and verification results.



`analysis/Evidence-Integrity-Record.csv`



Records the evidence-image baseline and post-analysis SHA-256 values.



`analysis/Forensic-Recovery-Analysis.txt`



Contains the forensic observations, recovery interpretation, attribution assessment, integrity assessment, limitations, and conclusion.



### Recovered Artifacts



`evidence/recovery/carved\_pdf\_001.pdf`



Complete PDF-like training artifact recovered through header/footer carving.



`evidence/recovery/carved\_pdf\_002.pdf`



Complete PDF-like training artifact recovered from source data that originally used a misleading `.jpg` extension.



`evidence/recovery/carved\_office\_fragment\_001.bin`



Partial 64-byte ZIP-style training fragment.



## Laboratory Limitations



This exercise used a deliberately constructed binary training image rather than a forensic image acquired from a production filesystem.



The PDF artifacts are simplified training artifacts and should not be treated as representative of every valid PDF structure.



The ZIP-style artifact is not a genuine Microsoft Excel workbook. It was deliberately constructed with a ZIP-style signature for recovery training.



The partial recovery was intentionally limited to 64 bytes to demonstrate uncertain boundaries and partial-artifact validation.



This laboratory does not reproduce all behavior associated with:



* NTFS deletion;

* fragmented files;

* SSD TRIM;

* garbage collection;

* overwritten sectors;

* compressed or encrypted files; or

* professional forensic carving software.



## Skills Demonstrated



This laboratory demonstrates practical experience with:



* deleted-data recovery concepts;

* signature-based file identification;

* raw binary evidence analysis;

* byte-offset analysis;

* header/footer carving;

* partial artifact recovery;

* SHA-256 validation;

* evidence-integrity verification;

* extension-versus-content analysis;

* cautious forensic attribution; and

* forensic reporting.



## Key Forensic Principle



`Recover → Validate → Correlate → Attribute`



Recovery establishes that data was found.



Validation establishes characteristics of the recovered data.



Correlation connects the artifact with other evidence.



Attribution requires sufficient evidence to support a specific identity, source, event, or actor.



These conclusions should not be treated as interchangeable.



## Conclusion



Day 06 demonstrated how signature-based carving can recover data from a controlled raw evidence image without relying on original filenames.



Two complete PDF-like training artifacts were recovered and validated against known sources using SHA-256.



A third ZIP-style artifact was intentionally recovered only partially, demonstrating why a partial artifact cannot be treated as a complete source file merely because its content is consistent with one.



The laboratory reinforces a central DFIR principle:



**Recover only what the evidence permits, validate what was recovered, and do not attribute beyond what the evidence supports.**



