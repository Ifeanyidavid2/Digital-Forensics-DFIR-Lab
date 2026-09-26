# Windows Registry Forensics Investigation Report

## Case Information

| Field | Value |
|---|---|
| Case ID | DFIR-D10 |
| Examination | Windows Registry Forensics |
| Evidence Type | Windows Registry hive snapshots |
| Integrity Algorithm | SHA-256 |
| Analysis Model | Source preservation with separate working copies |
| Acquisition Method | `reg.exe save` from loaded Registry namespaces |

---

## Executive Summary

A forensic examination of Windows Registry evidence was conducted to identify system configuration, startup and persistence-related configuration, USB storage information, user-profile associations, recent user-context artifacts, and Windows Shell state.

Six Registry hive snapshots were acquired and preserved:

- SYSTEM
- SOFTWARE
- SAM
- SECURITY
- NTUSER.DAT
- UsrClass.dat

The examination identified system and user-profile artifacts suitable for forensic correlation.

Notable findings included a SanDisk Ultra USB storage device recorded within SYSTEM hive artifacts, an associated `D:` drive mapping, a LocalSystem service referencing an executable within a user-profile directory, machine-level and user-level startup configuration, SID-to-profile association, RunMRU and TypedPaths activity, RecentDocs references, and substantial ShellBag data.

No Registry value specifically referencing an executable named `update.exe` was identified within the examined machine-level or user-level Run/RunOnce locations.

Targeted searches also did not identify a readable `Board-Financial-Plan-2027.xlsx` reference within the examined NTUSER and BagMRU locations.

These negative findings are limited to the evidence, locations, terms, and search methods examined and are not interpreted as proof of historical absence.

No finding from the Registry evidence alone established malware execution, physical-user attribution, file copying, data exfiltration, or malicious intent.

Post-analysis SHA-256 verification confirmed that all six preserved source hive snapshots continued to match their acquisition baselines.

---

## Investigation Objectives

The examination sought to determine what the acquired Registry evidence could establish regarding:

1. Windows system configuration.
2. Installed software.
3. Startup and persistence-related configuration.
4. User-profile association.
5. USB storage recognition and drive mappings.
6. User-context activity artifacts.
7. Windows Shell and ShellBag state.
8. Potential references to `update.exe`.
9. Potential references to the training-case filename `Board-Financial-Plan-2027.xlsx`.
10. Integrity of the preserved Registry evidence.

---

## Evidence Acquisition

The following Registry-aware snapshots were collected from loaded Registry namespaces.

| Evidence ID | Evidence | Registry Source |
|---|---|---|
| DFIR-D10-E001 | SYSTEM.hiv | HKLM\SYSTEM |
| DFIR-D10-E002 | SOFTWARE.hiv | HKLM\SOFTWARE |
| DFIR-D10-E003 | SAM.hiv | HKLM\SAM |
| DFIR-D10-E004 | SECURITY.hiv | HKLM\SECURITY |
| DFIR-D10-E005 | NTUSER-DAT.hiv | Loaded user SID |
| DFIR-D10-E006 | UsrClass-DAT.hiv | Loaded user Classes namespace |

The acquisition method produced Registry-aware snapshots using `reg.exe save`.

The resulting files are not represented as bit-for-bit physical copies of the underlying live hive files.

---

## Evidence Integrity

SHA-256 was used as the evidence-integrity algorithm.

### Acquisition Baselines

| Evidence | SHA-256 |
|---|---|
| SYSTEM.hiv | `E66871DD776136F3E59675846A51A386424CEDE98CD985FE2415DF46D21E22E8` |
| SOFTWARE.hiv | `4721873F6F60DB3DFA3F9E38FCC3192BE93A384C260D686D9084080B3563BB97` |
| SAM.hiv | `48515CCCE605E6EACA15EA43DA60C40907090515476DD27BC50D931A88E7AAD3` |
| SECURITY.hiv | `AFDC42A6923BE8E8DF1BD51D9B601C15CEC691315613539FBBF142C355CC87BD` |
| NTUSER-DAT.hiv | `1119094255FD9E36804FC67970DB06B05320CEEFBE860B7DF445C1326517662C` |
| UsrClass-DAT.hiv | `768EC15849FE0F8B84816BE27038975110B54319BE834FCDB3FE623BBF950B55` |

### Post-Analysis Verification

All six preserved source snapshots matched their acquisition hashes.

**Integrity result: 6/6 MATCH**

No source-evidence integrity discrepancy was identified.

---

## Examination Methodology

The examination followed the workflow:

`Preserve → Acquire → Hash → Verify → Create Working Copy → Analyze → Unload → Verify Source`

Source snapshots were preserved separately from working copies.

SYSTEM, SOFTWARE, NTUSER.DAT, and UsrClass.dat were examined through working copies loaded into temporary Registry namespaces.

The temporary namespaces were unloaded after examination.

Source hashes were subsequently recalculated and compared with their acquisition baselines.

SAM and SECURITY were acquired and integrity-verified but credential material was outside the scope of this exercise.

---

# Detailed Findings

## Finding 1 — SYSTEM Control Set

The SYSTEM snapshot recorded:

- Current: ControlSet001
- Default: ControlSet001
- LastKnownGood: ControlSet001
- Failed: 0

Only ControlSet001 was identified during the scoped examination.

### Assessment

This establishes the control-set state recorded within the acquired snapshot. It does not independently establish historical control-set configurations outside the acquired evidence.

---

## Finding 2 — Computer Name

The SYSTEM hive recorded:

`DESKTOP-PCML6D5`

### Assessment

This supports association of the acquired Registry snapshot with the system name recorded in the hive.

---

## Finding 3 — Service Configuration

The SYSTEM hive contained a service configuration for:

`NativePushService`

The ImagePath referenced:

`C:\Users\Ifean\AppData\Local\Wondershare\Wondershare NativePush\WsNativePushService.exe`

Additional configuration included:

- Start: 2
- Type: 16
- ObjectName: LocalSystem

### Assessment

A service configured to run as LocalSystem while referencing an executable beneath a user-profile path is noteworthy and appropriate for further correlation.

The Registry configuration alone does not establish that the executable was malicious, that it existed at the relevant time, that the service successfully executed, or that an attacker or particular human created it.

---

## Finding 4 — USB Storage and Mounted Devices

SYSTEM hive artifacts contained a SanDisk Ultra USB storage device instance.

MountedDevices data associated the identified SanDisk Ultra instance with:

`D:`

and with a recorded volume GUID.

A separate `E:` mapping was associated with a Generic Mass-Storage instance.

### Assessment

The evidence supports Windows having recorded these device and volume associations.

It does not independently establish:

- which person physically inserted the device;
- which files were transferred;
- whether a transfer occurred;
- whether confidential information was copied; or
- whether data was exfiltrated.

Additional filesystem, LNK, Jump List, event-log, endpoint, and device evidence would be required for stronger conclusions.

---

## Finding 5 — Operating-System Metadata

The SOFTWARE hive recorded:

- ProductName: Windows 10 Pro
- DisplayVersion: 22H2
- CurrentBuild: 22621
- EditionID: Professional
- InstallationType: Client

The values are reported exactly as observed in the acquired Registry artifact.

The recorded InstallDate value represented:

- 2025-07-10 14:02:27 UTC
- 2025-07-10 15:02:27 +01:00

### Assessment

The InstallDate value is treated as the timestamp represented by that Registry value rather than a complete installation or upgrade history.

The observed ProductName was retained as evidence rather than changed based on other system context.

---

## Finding 6 — Installed Software Inventory

The examined SOFTWARE uninstall locations contained 180 records.

### Assessment

These Registry entries support the presence of software installation/configuration records.

They do not independently establish that each application successfully executed or was actively used.

---

## Finding 7 — Machine-Level Startup Configuration

The examined 64-bit Run location contained:

- SecurityHealth
- NortonUI.exe
- Nearby Share

The examined WOW6432Node Run location contained:

- GrooveMonitor
- SunJavaUpdateSched
- Wondershare Helper Compact.exe

No populated value specifically referencing an executable named `update.exe` was identified within the four examined machine-level Run/RunOnce locations.

### Assessment

The identified entries establish startup configuration within the acquired snapshot.

The absence of an exact `update.exe` reference is a scoped negative finding. It does not establish that the executable never existed or that another persistence mechanism was not used.

---

## Finding 8 — SID and User-Profile Association

The SOFTWARE ProfileList data associated:

`S-1-5-21-272426600-1996297137-4257108005-1001`

with:

`C:\Users\Ifean`

### Assessment

This establishes a recorded relationship between the SID and user-profile path.

It does not attribute a specific activity to the physical human associated with the profile.

---

## Finding 9 — User-Level Startup Configuration

NTUSER.DAT contained Run entries for:

- OneDrive
- Adobe Acrobat Synchronizer
- Teams
- Google Chrome
- Microsoft Edge

No populated startup value was identified in the examined user RunOnce location.

No value specifically referencing an executable named `update.exe` was identified in the examined user Run/RunOnce locations.

### Assessment

The earlier `OneDriveUpdate → update.exe` example used during the knowledge exercise was hypothetical and was not identified in the acquired Day 10 evidence.

The negative result remains limited to the examined locations and snapshot.

---

## Finding 10 — RunMRU

NTUSER.DAT RunMRU contained recorded strings associated with:

- `prefetch`
- `MRT`
- `firefox.exe -P`

The recorded MRU order was:

`c → b → a`

### Assessment

RunMRU supports the presence and relative ordering of strings within the Run-dialog MRU artifact.

It does not independently establish successful execution, command outcome, or the physical identity of the person who entered the commands.

---

## Finding 11 — TypedPaths

NTUSER.DAT TypedPaths contained references including:

- Desktop
- Downloads
- This PC
- a search-ms path associated with `C:\Users\Ifean\Desktop\git-page`

### Assessment

The artifacts support Explorer-related navigation activity in the context of the acquired user profile.

They do not independently establish physical-user attribution.

---

## Finding 12 — Recent Excel Documents

The `.xlsx` RecentDocs artifact referenced:

1. GUs_DR_FOR__5_Jul_to_31_ Dec_2026.xlsx
2. DUES AND LEVIES.xlsx
3. Pentest_Intern_Headstart_Roadmap.xlsx
4. Policy_compliance_framework.xlsx
5. comprehensive_vehicle_checklist.xlsx

MRUListEx provided relative ordering but not exact interaction timestamps.

A targeted search did not identify:

`Board-Financial-Plan-2027.xlsx`

### Assessment

The RecentDocs data supports association of these filenames with the acquired user-profile context.

It does not independently prove that the physical user manually opened each document.

The absence of the training-case filename is a scoped negative and does not establish that the file never existed or was never accessed.

---

## Finding 13 — UsrClass.dat Shell State

UsrClass.dat contained:

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

The root MRUListEx represented all 62 numbered entries followed by a `-1` terminator.

### Assessment

This demonstrates substantial Windows Shell state within the acquired user Classes snapshot.

MRUListEx supports relative ordering but does not independently provide exact interaction timestamps.

---

## Finding 14 — ShellBag String Extraction

Best-effort examination of Shell Item binary data recovered readable fragments including:

- C:\
- D:\
- E:\
- F:\
- G:\
- Users
- Ifean
- AppData
- GitHub
- Desktop / DESKTO~1
- Documents / DOCUME~1
- Pictures
- CAMERA~1

### Assessment

These fragments are investigative leads.

Because a dedicated ShellBag parser was not used, the recovered strings were not treated as fully reconstructed paths.

The drive-letter references support shell-state information associated with multiple volumes but do not identify the underlying physical device or establish file copying.

---

## Finding 15 — Targeted ShellBag Searches

Recursive text searches of the examined BagMRU structure produced no readable matches for:

- `SanDisk`
- `Board-Financial-Plan-2027.xlsx`

### Assessment

These are scoped negative findings.

Failure to recover a readable string using this method does not establish that the device or file was never represented in ShellBag structures or encountered by the system.

---

# Evidentiary Assessment

## Established by the Examined Registry Evidence

The acquired evidence supports that:

- Windows recorded the examined system configuration.
- the system name was recorded as `DESKTOP-PCML6D5`;
- the NativePushService configuration referenced a user-profile executable path and LocalSystem account;
- a SanDisk Ultra USB storage instance was recorded;
- the identified SanDisk instance was associated with a `D:` mapping;
- a separate Generic Mass-Storage instance was associated with `E:`;
- installed-software records were present;
- machine and user startup entries were recorded;
- the identified SID was associated with `C:\Users\Ifean`;
- user-profile MRU, TypedPaths, RecentDocs, and Shell-state artifacts were present; and
- all preserved source evidence passed post-analysis SHA-256 verification.

## Not Established by Registry Evidence Alone

The examination does not establish:

- that `update.exe` was malware;
- that `update.exe` persisted through the examined Run locations;
- that NativePushService was malicious;
- that a particular executable successfully ran merely because Registry configuration referenced it;
- that Ifean personally performed a particular recorded action;
- that a specific person physically inserted the SanDisk device;
- that `Board-Financial-Plan-2027.xlsx` was copied to removable media;
- that confidential information was exfiltrated;
- that absence from a searched Registry location proves historical absence; or
- malicious intent.

---

# Analysis Limitations

1. The Registry snapshots were produced from loaded namespaces using `reg.exe save` and are not claimed to be bit-for-bit physical copies of the underlying live hive files.

2. The host was active during acquisition. The resulting snapshots represent Registry state captured through the selected acquisition method.

3. ShellBag binary data was examined through best-effort ASCII/UTF-16 string extraction rather than a dedicated ShellBag parser.

4. Full Shell Item path reconstruction was therefore outside the scope of the examination.

5. Registry-provider methods used during the exercise did not expose reliable LastWriteTime information for every examined user-activity key.

6. Negative searches apply only to the acquired snapshots, locations, search terms, and methods examined.

7. SAM and SECURITY were preserved and integrity-verified, but credential hashes, secrets, and credential-related analysis were intentionally outside scope.

8. Registry artifacts should be correlated with additional evidence before conclusions about execution, maliciousness, human attribution, file transfer, or exfiltration are made.

---

# Recommendations for Further Correlation

Where stronger conclusions are required, Registry findings should be correlated with:

- Windows Event Logs;
- PowerShell Operational logs;
- Prefetch;
- Amcache;
- LNK files;
- Jump Lists;
- `$MFT`;
- `$UsnJrnl`;
- `$LogFile`;
- endpoint/EDR telemetry;
- network telemetry;
- removable-media filesystem evidence; and
- file hashes and metadata.

For the NativePushService finding, useful follow-up evidence would include the referenced executable's existence, SHA-256 hash, digital signature, PE metadata, creation timestamps, Prefetch/Amcache records, service-start events, parent/process telemetry, and network activity.

For the SanDisk device, useful follow-up evidence would include device-installation timestamps, volume information, LNK and Jump List references, filesystem metadata, removable-media contents, and correlated user/session telemetry.

---

# Conclusion

The Day 10 examination successfully demonstrated the forensic value and limitations of Windows Registry evidence.

The acquired Registry snapshots contained useful system, persistence-related, USB, user-profile, MRU, RecentDocs, and Shell-state artifacts.

The evidence supported multiple system and profile associations but did not independently establish malware execution, physical-user attribution, file transfer, exfiltration, or malicious intent.

The investigation therefore applies the following reasoning model:

> **Observation → Context → Correlation → Hypothesis → Testing → Supported Conclusion**

All six preserved source Registry hive snapshots retained their acquisition SHA-256 values after analysis.

**Final integrity status: 6/6 MATCH.**

