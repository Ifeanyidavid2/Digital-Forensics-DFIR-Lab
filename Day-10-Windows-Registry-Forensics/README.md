# Day 10 — Windows Registry Forensics

## Overview

Day 10 focuses on Windows Registry forensics and the evidentiary value of machine-level and user-level Registry artifacts.

The investigation demonstrates how Registry evidence can support conclusions about system configuration, installed software, persistence locations, user-profile associations, USB device recognition, drive-letter mappings, recent user-context activity, and Windows Shell state.

The central forensic principle for this lab is:

> **Registry presence establishes recorded configuration or state. Interpretation requires context, correlation, and corroboration.**

A Registry artifact should not automatically be interpreted as proof of maliciousness, successful execution, physical-user attribution, file transfer, exfiltration, or human intent.

---

## Case Information

- **Case ID:** DFIR-D10
- **Investigation Type:** Windows Registry Forensics
- **Platform:** Windows
- **Acquisition Method:** Registry-aware snapshots using `reg.exe save`
- **Integrity Algorithm:** SHA-256
- **Analysis Method:** Preserved source evidence with separate working copies

---

## Registry Evidence Acquired

Six Registry hive snapshots were collected:

| Evidence ID | Hive | Source |
|---|---|---|
| DFIR-D10-E001 | SYSTEM.hiv | HKLM\SYSTEM |
| DFIR-D10-E002 | SOFTWARE.hiv | HKLM\SOFTWARE |
| DFIR-D10-E003 | SAM.hiv | HKLM\SAM |
| DFIR-D10-E004 | SECURITY.hiv | HKLM\SECURITY |
| DFIR-D10-E005 | NTUSER-DAT.hiv | User SID namespace |
| DFIR-D10-E006 | UsrClass-DAT.hiv | User Classes namespace |

The saved hives are Registry-aware snapshots from loaded Registry namespaces. They are not claimed to be bit-for-bit copies of the underlying live hive files.

---

## Evidence Integrity

SHA-256 hashes were recorded during acquisition and verified after analysis.

All six preserved source hive snapshots matched their acquisition baselines during post-analysis verification.

**Result: 6/6 MATCH**

No source-evidence integrity discrepancy was identified.

---

## SYSTEM Hive Findings

The SYSTEM hive was examined for system configuration, services, USB storage information, and mounted-volume information.

### Control Set

The acquired snapshot recorded:

- Current: ControlSet001
- Default: ControlSet001
- LastKnownGood: ControlSet001
- Failed: 0

Only ControlSet001 was identified during the scoped examination.

### Computer Name

The recorded computer name was:

`DESKTOP-PCML6D5`

### Service Configuration

A service named `NativePushService` referenced:

`C:\Users\Ifean\AppData\Local\Wondershare\Wondershare NativePush\WsNativePushService.exe`

The service configuration recorded:

- Start: 2
- Type: 16
- ObjectName: LocalSystem

This is noteworthy because a LocalSystem service references an executable within a user-profile path.

However, the Registry entry alone does **not** establish that:

- the executable is malicious;
- the executable was present at analysis time;
- the service successfully executed;
- an attacker created the service; or
- a specific human created the configuration.

### USB Storage

USBSTOR contained information referencing a SanDisk Ultra USB storage device.

A SanDisk Ultra instance was associated with a recorded `D:` drive-letter mapping in MountedDevices and with a volume GUID.

A separate `E:` mapping was associated with a Generic Mass-Storage instance.

This evidence supports Windows having recorded these device/volume relationships. It does not independently establish who physically connected a device, what files were copied, or whether information was exfiltrated.

---

## SOFTWARE Hive Findings

### Operating-System Metadata

The acquired SOFTWARE hive recorded:

- ProductName: Windows 10 Pro
- DisplayVersion: 22H2
- CurrentBuild: 22621
- EditionID: Professional
- InstallationType: Client

The Registry value is reported exactly as observed rather than silently normalizing the ProductName based on other system context.

The recorded InstallDate value converted to:

- UTC: 2025-07-10 14:02:27 UTC
- Local: 2025-07-10 15:02:27 +01:00

This represents the timestamp encoded by that Registry value and is not treated as a complete operating-system installation or upgrade history.

### Installed Software

The examined uninstall locations contained 180 software records.

These records support software-installation/configuration evidence but do not establish that every listed application was executed.

### Machine Startup Locations

The examined 64-bit Run location included:

- SecurityHealth
- NortonUI.exe
- Nearby Share

The examined WOW6432Node Run location included:

- GrooveMonitor
- SunJavaUpdateSched
- Wondershare Helper Compact.exe

No Registry value specifically referencing an executable named `update.exe` was identified in the four examined machine-level Run/RunOnce locations.

This is a scoped negative finding and does not prove that `update.exe` never existed, executed, or persisted through another mechanism.

### Profile Association

The SID:

`S-1-5-21-272426600-1996297137-4257108005-1001`

was mapped to:

`C:\Users\Ifean`

This supports SID-to-profile association. It does not by itself attribute a specific action to the human user.

---

## NTUSER.DAT Findings

### User Startup Configuration

The examined user Run key contained startup entries for:

- OneDrive
- Adobe Acrobat Synchronizer
- Teams
- Google Chrome
- Microsoft Edge

No populated startup value was identified in the examined RunOnce location.

No Registry value specifically referencing an executable named `update.exe` was identified in the examined user Run/RunOnce locations.

The earlier training example involving `OneDriveUpdate` and `update.exe` was hypothetical and was not identified in the acquired Day 10 evidence.

### RunMRU

RunMRU recorded:

- `prefetch`
- `MRT`
- `firefox.exe -P`

MRUList recorded the relative order:

`c → b → a`

These artifacts support recorded Run-dialog MRU strings. They do not independently establish successful command execution or prove which physical person entered them.

### TypedPaths

TypedPaths contained references including:

- Desktop
- Downloads
- This PC
- a search-ms path associated with `C:\Users\Ifean\Desktop\git-page`

These support Explorer-related navigation activity within the user-profile context, not physical-user attribution.

### Recent Excel Documents

The `.xlsx` RecentDocs artifact contained references including:

- GUs_DR_FOR__5_Jul_to_31_ Dec_2026.xlsx
- DUES AND LEVIES.xlsx
- Pentest_Intern_Headstart_Roadmap.xlsx
- Policy_compliance_framework.xlsx
- comprehensive_vehicle_checklist.xlsx

MRUListEx provided relative ordering but not exact interaction timestamps.

A targeted search returned no match for:

`Board-Financial-Plan-2027.xlsx`

This is a scoped negative finding and does not establish that the file never existed or was never accessed.

---

## UsrClass.dat and ShellBag Findings

The Windows Shell key contained:

- BagMRU
- Bags
- MuiCache

BagMRU contained:

- 62 immediate subkeys
- 65 values
- NodeSlots
- NodeSlot
- MRUListEx
- numbered entries 0 through 61

The root MRUListEx contained all 62 numbered entries followed by a `-1` terminator.

Best-effort string extraction from Shell Item binary data recovered fragments including:

- `C:\`
- `D:\`
- `E:\`
- `F:\`
- `G:\`
- Users
- Ifean
- AppData
- GitHub
- Desktop / DESKTO~1
- Documents / DOCUME~1
- Pictures
- CAMERA~1

These fragments were treated as investigative leads rather than fully parsed paths because a dedicated ShellBag parser was not used.

A targeted BagMRU text search returned no readable match for:

- `SanDisk`
- `Board-Financial-Plan-2027.xlsx`

These are scoped negative results and do not establish historical absence.

---

## SAM and SECURITY Hives

SAM and SECURITY snapshots were acquired and integrity-verified for evidentiary completeness.

Credential hashes, LSA secrets, and other credential material were outside the scope of this Day 10 exercise and were not extracted.

---

## Forensic Interpretation

The investigation demonstrates several important distinctions:

### Registry Presence ≠ Maliciousness

A Registry value may be legitimate, suspicious, or malicious depending on context. Presence alone does not determine intent.

### User Hive ≠ Human Attribution

An artifact within NTUSER.DAT or UsrClass.dat associates activity or configuration with a user-profile context. It does not automatically prove that the named human personally performed the action.

### Service Configuration ≠ Execution

A service Registry entry establishes recorded service configuration. It does not independently establish that its executable existed, successfully ran, or was malicious.

### USB Recognition ≠ Exfiltration

USB Registry artifacts may establish that Windows recognized or recorded a storage device and may help correlate volume mappings.

They do not independently prove:

- who physically connected the device;
- which files were copied;
- whether copying occurred; or
- whether confidential information was stolen.

### Absence ≠ Historical Absence

Failure to locate a Registry value in the examined hive or location does not establish that the value never existed.

Possible explanations include:

- another persistence mechanism;
- deletion of the value;
- another hive or Registry location;
- another control set;
- evidence from a different point in time;
- incomplete acquisition;
- search-method limitations.

---

## Analysis Limitations

- Registry snapshots were acquired from loaded Registry namespaces using `reg.exe save`.
- They are not claimed to be bit-for-bit physical copies of the underlying live hive files.
- ShellBag structures were examined using best-effort string extraction rather than a dedicated ShellBag parser.
- Registry-provider methods used during this exercise did not provide reliable LastWriteTime values for all examined user-activity keys.
- Negative searches are scoped to the specific hives, locations, terms, and methods examined.
- Registry artifacts alone are insufficient for many questions involving execution, maliciousness, physical-user attribution, file transfer, or exfiltration.

---

## Evidence Handling

Source hive snapshots were preserved separately from working copies.

The workflow followed:

`Preserve → Acquire → Hash → Verify → Analyze Working Copy → Verify Source`

Post-analysis SHA-256 verification produced:

**6/6 MATCH**

---

## Repository Storage Note

Raw and working Registry hive snapshots are intentionally excluded from Git.

This prevents large binary evidence files—particularly the approximately 105.25 MiB SOFTWARE snapshots—from being committed to the repository.

The repository retains:

- acquisition metadata;
- SHA-256 hashes;
- analysis findings;
- integrity-verification results;
- limitations; and
- forensic documentation.

---

## Key Lesson

> **Registry evidence tells us what Windows recorded. Correlation tells us what that evidence may mean. Attribution requires additional evidence.**

The appropriate reasoning model is:

`Observation → Context → Correlation → Hypothesis → Testing → Supported Conclusion`

