# Day 12 - Windows USB Device Forensics Report

## Executive Summary
The SYSTEM registry examination identified multiple USBSTOR entries, corresponding USB enumeration records for a SanDisk Ultra and a Generic Mass-Storage device, and drive-letter correlations for D: and E:. The F: mapping remains unresolved. The working-copy SHA-256 differs from the recorded baseline, so this limitation is disclosed.

## Scope and Method
The working registry hive was mounted under HKLM\DFIR_D12_SYSTEM. Queries examined ControlSet001\Enum\USBSTOR, ControlSet001\Enum\USB, MountedDevices, and Select. The hive was subsequently unloaded successfully.

## Key Findings
1. USBSTOR contains SanDisk Ultra, Generic Mass-Storage, and two WDC WD10 JPVX-75JC3T0 entries with distinct instance identifiers.
2. The SanDisk Ultra entry VID_0781&PID_558A and Generic Mass-Storage entry VID_349C&PID_0418 have corresponding USB enumeration records with matching ContainerIDs.
3. MountedDevices correlates D: with the SanDisk Ultra USBSTOR instance and E: with the Generic Mass-Storage USBSTOR instance. F: was observed, but its mapping was not resolved from the entries examined.
4. The Select key reported Current=1, Default=1, Failed=0, and LastKnownGood=1; ControlSet001 was used for the queries.
5. Two DEVICE_DESCRIPTOR_FAILURE entries were observed. These do not establish that the devices were storage devices or malicious.

## Integrity Assessment
The Day 10 acquisition register records the original SYSTEM.hiv SHA-256 as E66871DD776136F3E59675846A51A386424CEDE98CD985FE2415DF46D21E22E8. The current source hash matches this recorded baseline.

The Day 12 working copy produced SHA-256 61618E84FB3CC31DEE3A3A45E8387670E97D8F3BF24A0FEFDD8A17B4ADB290D5 after the hive was unloaded. This differs from the recorded baseline. The cause and time of change are undetermined. See analysis\Integrity-Verification.csv.

## Limitations
Registry enumeration and drive-letter correlations do not independently prove file copying, transfer, or exfiltration. These findings do not establish user intent, human attribution, or exact device connection times. The separate SanDisk descriptor has not been established as the same physical device as the SanDisk Ultra entry. The working-copy integrity discrepancy must be considered when assessing confidence in these findings.

## Recommendations
- Preserve the original Day 10 source and existing integrity records.
- Retain the working-copy hash discrepancy in the case documentation.
- Assess the provenance and integrity of the working copy before relying on it for additional analysis.
- Correlate these registry findings with independent forensic artifacts before making claims about file access or transfer.
