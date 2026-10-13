# Day 11 - Windows User Activity Forensics

## Case Information

- Case ID: DFIR-2026-007
- Subject context: Windows user activity artifacts associated with the Ifean user profile
- Purpose: Correlate shortcut, application recent-file, ShellBag, and SYSTEM hive artifacts while preserving evidential limitations.

## Scope and Methodology

The examination considered 470 Recent LNK shortcuts, Windows RecentDocs and RunMRU records, WPS RecentFiles records, ShellBag parser output derived from a working copy of the preserved UsrClass hive, and drive-letter mappings in a working copy of the preserved SYSTEM hive. Artifact acquisition was checked using recorded source and acquired-file hashes. The SYSTEM hive was examined through the mounted working copy under HKLM\DFIR_D11_SYSTEM; the preserved source was not mounted. The active control set was identified as ControlSet001 from Select\Current=1. Findings were correlated across artifact families rather than treating any single artifact as conclusive.

## Findings

### 1. Recent LNK shortcuts

Of 470 examined Recent LNK shortcuts, three referenced targets under `F:\Math lesson`. Their shortcut LastWrite times were recorded on 23 June 2026 at 12:39:30, 12:42:50, and 13:05:41. These times describe shortcut metadata and must not be treated as exact file-open, copy, or transfer times. The parser used WScript.Shell COM and provided limited metadata; target MAC times, volume serial details, and tracker data were not established by this method.

### 2. WPS RecentFiles

The WPS RecentFiles dataset contained 22 records referencing PowerPoint files under `F:/Math lesson`. Six additional records referenced `D:/Math Lessons to Upload`, including lesson-related filenames. Application recent-file records support a history of application-level references, but do not independently establish file copying, successful transfer, or the identity of the person operating the system.

### 3. ShellBags

The SBECmd output contained 42 decoded records with `Math lesson` in the path, including `Desktop\This PC\F:\Math lesson`, `Desktop\F:\\Math lesson`, and related child folders. Records also referenced `D:\\Math Lessons to Upload` and its child folders. The parser reported an exception involving BagMRU slot 9, Type `0x2E`, and an extension-block mismatch, but continued processing. The parser accepted no `--tz` option, so no explicit timezone conversion was performed. Interpret parser timestamps with this limitation in mind.

### 4. SYSTEM drive mappings

The examined `MountedDevices` data contained an exact binary match between `D:` and `Volume{489ba1c2-1ba5-11f1-9343-7c7635a32973}`, associated with a SanDisk Ultra USBSTOR instance `4C530001120320106312&0`. The `E:` mapping matched `Volume{6e90e62a-e2e4-11f0-9334-7c7635a32973}`, associated with a Generic Mass-Storage instance `20240418000000&0`. The related Partmgr DiskId GUIDs differ slightly from their respective volume GUIDs and should not be treated as interchangeable identifiers.

The `F:` mapping contained the 12-byte value `34-91-8B-60-00-00-10-00-00-00-00-00`. No exact matching volume entry was identified among the entries examined. Its device association therefore remains unresolved. Other examined mappings, including `C:` and `G:`, were not resolved to a matching volume entry in the examined set. A separate SanDisk 3.2Gen1 descriptor was observed, but the available evidence does not establish that it represents the same physical device as the SanDisk Ultra.

### 5. Cross-artifact correlation

The three Recent LNK targets, 22 WPS RecentFiles records, and decoded ShellBag paths independently reference `F:\Math lesson` or its slash-normalized equivalent. This cross-artifact consistency supports a conclusion that the path was represented in multiple Windows and application activity artifacts. The `D:\Math Lessons to Upload` references provide a separate correlation lead, not proof that files were copied from `F:` to `D:`.

### 6. Other user activity artifacts

The examined RecentDocs `.xlsx` MRU ordering placed `GUs_DR_FOR__5_Jul_to_31_ Dec_2026.xlsx` first, followed by `DUES AND LEVIES.xlsx`, `Pentest_Intern_Headstart_Roadmap.xlsx`, `Policy_compliance_framework.xlsx`, and `comprehensive_vehicle_checklist.xlsx`. This is a relative MRU order, not a timestamped sequence. No spreadsheet-specific Recent LNK filename was identified among the 470 examined shortcuts; this absence is limited to that examined dataset. RunMRU strings included `prefetch\1`, `MRT\1`, and `firefox.exe -P\1`, but these strings alone do not establish that the associated commands executed successfully.

## Limitations

- Registry and application artifacts can show recorded references or historical state; they do not, individually, establish who physically operated the computer.
- Drive-letter assignments can change over time. The unresolved `F:` mapping cannot be assigned to a particular physical device from the examined mappings alone.
- Shortcut LastWrite times, ShellBag parser timestamps, and MRU ordering have different meanings and must not be merged into one precise event timeline without corroboration.
- The ShellBag parser reported an exception and extension-block mismatch; some records or metadata may not have been decoded fully.
- No explicit timezone conversion was applied to the ShellBag parser output.
- The examined artifacts do not prove that files were copied, transferred, uploaded, or exfiltrated. They also do not establish intent or physical-human attribution.
- The SHA256 values in the correlation CSV must be interpreted according to the specific artifact each value identifies; a hash of a verification CSV is not the hash of the underlying LNK collection.

## Defensible Conclusion

Multiple artifact families record references to `F:\Math lesson` in the examined Windows user-activity evidence. WPS records and ShellBag paths also reference `D:\Math Lessons to Upload`, while SYSTEM hive mappings associate `D:` with a SanDisk Ultra instance and `E:` with a Generic Mass-Storage instance. The examined evidence does not resolve the `F:` mapping to a specific device and does not establish that lesson files were copied or exfiltrated. The findings should be treated as correlated activity indicators and investigative leads, not proof of a file transfer or attribution to a specific person.

## Supporting Analysis Artifact

- `analysis\Day11-Evidence-Correlation.csv`
- Correlation CSV SHA256: `065F7C5CD31BAFEFFF1B6B853D282AA7DB6399C4EED6FFDA70F14D452B827B04`
- This report documents the current interpretation and limitations; it does not replace the underlying evidence, acquisition verification records, or parser output.
