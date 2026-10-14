# Day 12 - Windows USB Device Forensics

## Objective
Examine SYSTEM registry evidence for USB device enumeration, device identifiers, drive-letter correlations, and control-set selection.

## Evidence and Method
- Source artifact: Day 10 SYSTEM.hiv acquisition artifact.
- Working copy: evidence\SYSTEM-D11-Reference-Working.hiv.
- Registry hive was mounted under HKLM\DFIR_D12_SYSTEM and subsequently unloaded successfully.
- Queried ControlSet001\Enum\USBSTOR, ControlSet001\Enum\USB, MountedDevices, and Select.

## USBSTOR Findings
The registry contained entries for:
- SanDisk Ultra USB Device, instance 4C530001120320106312&0.
- Generic Mass-Storage USB Device, instance 20240418000000&0.
- Two WDC WD10 JPVX-75JC3T0 USB Device entries with different instance identifiers.

These entries indicate recorded device enumeration. The two WDC entries should not be assumed to represent the same physical device without corroborating evidence.

## USB Enumeration Findings
The SanDisk Ultra entry (VID_0781&PID_558A) and Generic Mass-Storage entry (VID_349C&PID_0418) have corresponding USB enumeration records with matching ContainerIDs.

Two DEVICE_DESCRIPTOR_FAILURE entries were observed under VID_0000&PID_0002, with EnumerationFailureCode 0x40010000. These failures do not establish that the devices were storage devices or malicious.

## Drive-Letter Correlations
- D: maps to the SanDisk Ultra USBSTOR instance 4C530001120320106312&0.
- E: maps to the Generic Mass-Storage USBSTOR instance 20240418000000&0.
- F: was observed in MountedDevices, but its mapping remains unresolved from the entries examined.
- A separate SanDisk descriptor was observed; available evidence does not establish that it represents the same device as the SanDisk Ultra entry.

Partmgr DiskId values and volume GUIDs are distinct identifiers and must not be conflated.

## Control-Set Selection
The Select key reported Current=1, Default=1, Failed=0, and LastKnownGood=1. ControlSet001 was therefore selected for the registry queries.

## Integrity Assessment
The Day 10 acquisition register and post-analysis integrity record list the original SYSTEM.hiv SHA-256 as E66871DD776136F3E59675846A51A386424CEDE98CD985FE2415DF46D21E22E8. The current Day 10 source hash matches that recorded value.

The Day 12 working copy produced SHA-256 61618E84FB3CC31DEE3A3A45E8387670E97D8F3BF24A0FEFDD8A17B4ADB290D5 after the hive was unloaded. This differs from the recorded baseline. The cause and time of change are undetermined. See analysis\Integrity-Verification.csv.

## Limitations
Registry enumeration and drive-letter correlations do not, by themselves, prove that a file was copied, transferred, or exfiltrated. These findings do not establish user intent, human attribution, or exact device connection times. The F: mapping remains unresolved. The working-copy integrity discrepancy must be disclosed and assessed before relying on the copy for further analysis.
