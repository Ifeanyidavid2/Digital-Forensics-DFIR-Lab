# Day 13 — Windows Execution Artifacts Forensics Report

## 1. Executive Summary

This investigation examined Windows Prefetch artifacts in `C:\Windows\Prefetch`. The work included directory enumeration, inventory creation, SHA-256 manifest generation, filename reconciliation, and follow-up hash verification. The Prefetch directory was accessible for enumeration using Administrator PowerShell.

The initial inventory recorded 301 files. A later inventory recorded 308 files. Verification of the later SHA-256 manifest identified 14 files whose current hashes differed from the recorded values. The cause of these differences has not been established.

## 2. Objectives

- Inventory available Windows Prefetch files.
- Record filenames, file sizes, and modification timestamps.
- Generate SHA-256 manifests for separate observations.
- Compare inventory snapshots and investigate hash discrepancies.
- Document findings, limitations, and evidence-handling recommendations.

## 3. Scope and Methodology

**Source directory:** `C:\Windows\Prefetch` 
**Working directory:** `C:\Users\Ifean\Digital-Forensics-DFIR-Lab\Day-13-Windows-Execution-Artifacts-Forensics` 
**Collection context:** Administrator PowerShell on 14 October 2026, local offset +01:00.

The investigation used PowerShell directory enumeration, CSV inventory exports, SHA-256 hashing, filename comparisons, file metadata inspection, and repeated hash observations. The source Prefetch files were examined in place. This work did not include forensic parsing of Prefetch binary contents or acquisition of a forensic image.

## 4. Inventory Results

- Initial inventory: 301 files.
- Initial SHA-256 manifest: 306 entries.
- Later inventory: 308 files.
- Later SHA-256 manifest: 308 entries with 308 unique filenames and valid 64-character hexadecimal hash values.
- Seven filenames in the later directory comparison were absent from the original inventory.
- No original inventory filenames were missing during the later comparison.

The five additional entries found in the initial hash manifest were DLLHOST.EXE-F7FC6593.pf, ONEAPP.IGCC.WINSERVICE.LACE.E-11F007EC.pf, SVCHOST.EXE-117C4441.pf, SVCHOST.EXE-A1099EF2.pf, and SVCHOST.EXE-FA38241C.pf.

The seven filenames found in the later directory comparison were:

1. DLLHOST.EXE-F7FC6593.pf
2. ENGSUP.EXE-32508797.pf
3. ONEAPP.IGCC.WINSERVICE.LACE.E-11F007EC.pf
4. SVCHOST.EXE-117C4441.pf
5. SVCHOST.EXE-A1099EF2.pf
6. SVCHOST.EXE-FA38241C.pf
7. WMIAPSRV.EXE-FC8436DD.pf

## 5. Integrity Verification Findings

Subsequent verification of the later SHA-256 manifest reported 14 hash mismatches and no missing source files. A focused examination of CHROME.EXE-AED7BA3D.pf returned different SHA-256 values across successive observations. One five-second check returned matching hashes for its two measurements; a later observation recorded another hash and an updated modification timestamp.

At the observation recorded at 2026-10-14 16:43:13 +01:00, the Chrome Prefetch file was 12,887 bytes, its LastWriteTime was 2026-10-14 16:40:51, and its SHA-256 was 0A56D68BAFF8428374CED5F22F1EFDA39750F3B63A30A64E56F89E8CD3C7F0AA.

The changing observations are consistent with the file being updated between some checks, but the exact cause has not been established. The hash mismatches alone do not prove tampering or malicious activity.

## 6. Artifacts Produced

- `analysis\Prefetch-Inventory.csv` — initial inventory.
- `analysis\Prefetch-Inventory-Current.csv` — later inventory.
- `analysis\Prefetch-SHA256-Manifest.csv` — initial hash manifest.
- `analysis\Prefetch-SHA256-Manifest-Current.csv` — later hash manifest.
- `notes\Day-13-Investigation-Notes.md` — investigation notes and observations.

The evidence folder was not used to store copies of the source Prefetch files during these steps.

## 7. Limitations

- The exact timing and cause of directory changes and hash mismatches remain undetermined.
- Prefetch filenames and filesystem modification timestamps do not independently prove exact execution times, user identity, or intent.
- No conclusions about malicious execution or tampering can be made from the recorded mismatches alone.
- The binary contents of the Prefetch files were not parsed in this investigation.
- No independent corroboration from Amcache, Shimcache, Windows event logs, or other execution artifacts is included in these findings.

## 8. Recommendations

1. Preserve the original inventories and manifests unchanged.
2. Treat each later inventory or manifest as a separate observation with its own collection time.
3. For future collection, document the acquisition method and timestamps, preserve source files appropriately, and hash the collected copies.
4. Parse relevant Prefetch files with an appropriate forensic tool and correlate the results with independent execution artifacts.
5. Investigate discrepancies before attributing them to a user, process, or malicious activity.

## 9. Conclusion

The investigation established that Prefetch artifacts were available and that the observed directory contents and file hashes were not consistent across all collection observations. Separate inventories and manifests were retained to document the different observed states. The cause of the changes remains unresolved. Further artifact parsing and correlation are required before drawing conclusions about particular program executions or potential malicious activity.

