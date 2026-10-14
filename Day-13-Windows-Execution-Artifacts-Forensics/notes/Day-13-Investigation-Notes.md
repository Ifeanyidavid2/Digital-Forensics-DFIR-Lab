# Day 13 — Windows Execution Artifacts Forensics

## Investigation Overview

**Objective:** Inventory Windows Prefetch artifacts, establish SHA-256 integrity baselines, and document changes observed during collection.

**Source directory:** C:\Windows\Prefetch
**Working directory:** C:\Users\Ifean\Digital-Forensics-DFIR-Lab\Day-13-Windows-Execution-Artifacts-Forensics
**Collection context:** Commands were run in Administrator PowerShell on 14 October 2026 (+01:00).

## Evidence and Analysis

### Prefetch Inventory Findings

- Initial Prefetch inventory: 301 files.
- Initial SHA-256 manifest: 306 entries.
- Current Prefetch inventory: 308 files.
- Current SHA-256 manifest: 308 entries, with 308 unique filenames and no invalid SHA-256 formats detected.
- Seven filenames were present in the current directory but absent from the original inventory.
- No filenames from the original inventory were missing during the later comparison.
- The original inventory and manifests were retained as separate snapshots.

**Interpretation:** The observed counts and filename differences indicate that the Prefetch directory changed between observations. The exact timing and cause of those changes have not been established.

### SHA-256 Verification Findings

- The initial SHA-256 manifest contained 306 entries, all with valid 64-character hexadecimal hash values.
- The current SHA-256 manifest contained 308 entries, with 308 unique filenames and valid hash formats.
- Subsequent verification identified 14 files whose current SHA-256 hashes differed from the recorded values.
- No missing source files were reported by that verification command.
- A focused check of CHROME.EXE-AED7BA3D.pf produced different hash values across successive observations.
- A five-second check returned matching hashes at that particular observation; a later observation showed a different hash and an updated LastWriteTime.

**Interpretation and limitations:** These results establish that the recorded hashes did not consistently match later observations. Changes to live Prefetch files during Windows activity are one possible explanation, but the exact cause has not been established. The findings do not independently prove malicious tampering or identify who caused any change. Original manifests should remain unchanged.

### Additional Prefetch Filenames

The following seven filenames were present in the later directory comparison but absent from the original inventory:

1. DLLHOST.EXE-F7FC6593.pf
2. ENGSUP.EXE-32508797.pf
3. ONEAPP.IGCC.WINSERVICE.LACE.E-11F007EC.pf
4. SVCHOST.EXE-117C4441.pf
5. SVCHOST.EXE-A1099EF2.pf
6. SVCHOST.EXE-FA38241C.pf
7. WMIAPSRV.EXE-FC8436DD.pf

These filename differences document a change in the observed directory contents. The filenames alone do not establish malicious activity, exact creation times, or the identity of a user or process responsible.

### Chrome Prefetch Case Study

**File:** CHROME.EXE-AED7BA3D.pf

The following SHA-256 values were observed at different points during the investigation:

- Initial manifest value: 75B94786472EEF16B1F5FE2D7A7250AF40A861EC20009C497C1C61DC2E232887
- Focused recheck: FD67F7E7592AEE57C1A65DF01A1D7FB295C0A45E0D1AE3B08A09D082787AB211
- First five-second check: 94DF6CE0188D81CC87B26AE9000E25C05CAB8BC1D2E3A1D2AD6678EA49FC4EC5
- Second five-second check: 07996961A10DE49E9F0CD27166DE74B935A63223F07CB05287CDA1592E893884
- Later metadata observation: B4E9A170EBE518EE462D59846A217303B4C66FAAB025E5A12565944E3989C724
- Timestamped observation at 2026-10-14 16:43:13 +01:00: 0A56D68BAFF8428374CED5F22F1EFDA39750F3B63A30A64E56F89E8CD3C7F0AA

At the 16:43:13 observation, the file size was 12,887 bytes and LastWriteTime was 2026-10-14 16:40:51. A separate five-second check returned matching hashes at the two measurements taken during that check.

**Interpretation:** The successive observations contain different hash values, and the recorded modification time advanced. The file was stable during one short check but was not consistently represented by the same hash across all observations. The precise cause of these changes remains undetermined. These observations alone do not establish malicious tampering.

### Investigation Conclusion

The investigation confirmed that Windows Prefetch artifacts were accessible with Administrator privileges. The initial inventory contained 301 files, while a later inventory contained 308. Seven filenames were absent from the original inventory, and no original inventory filenames were missing during the later comparison.

The current SHA-256 manifest recorded 308 unique files with valid hash formats. Subsequent verification identified 14 hash mismatches. Repeated observations of CHROME.EXE-AED7BA3D.pf also produced different SHA-256 values and an advancing LastWriteTime.

**Limitations:** The cause and exact timing of the directory and file changes have not been established. Prefetch filenames, modification timestamps, and hash differences alone do not establish malicious execution, user identity, intent, or tampering.

**Evidence-handling recommendation:** Preserve the original inventory and manifests unchanged. Treat each later inventory or hash manifest as a separate observation. For future collection, record timestamps, hash collected copies, and correlate Prefetch evidence with independent sources such as Windows event logs, Amcache, Shimcache, and other relevant artifacts before reaching attribution or incident conclusions.
