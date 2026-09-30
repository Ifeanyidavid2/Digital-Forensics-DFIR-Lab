# PeopleSoft URL Detection — Investigator Assessment

Date: 2026-09-29
Data source: Synthetic exercise events
Output: Detection-Results.csv

## WEB01
- Raw request: /%50SEMHUB/hub
- Normalized request: /PSEMHUB/hub
- Related event: java.exe spawned cmd.exe 18 seconds later on the same host.
- Assessment: High-priority simulated investigation lead. The timing and process relationship warrant investigation; the sample does not prove exploitation.

## WEB02
- Raw request: /PSEMHUB/hub
- Related process event: None present in the sample.
- Assessment: Request-level lead. Check exposure, response, and surrounding logs before drawing a conclusion.

## Limitations
The events were constructed for this exercise. They contain no source IP, HTTP response, process command line, user identity, or actual PeopleSoft host evidence.

## Live Wazuh validation — 30 September 2026

The Ubuntu agent (002, osboxes) collected Apache access logs and sent them to the Wazuh manager.

- Encoded request `/%50SEMHUB/hub`: custom rule 100101, level 7.
- Plain request `/PSEMHUB/hub`: custom rule 100101, level 7.
- Control request `/ordinary-lab-check`: built-in rule 31101, level 5; custom rule 100101 did not match.

Apache returned HTTP 404 for these requests. The alerts establish that the requests were logged and detected; they do not establish that PeopleSoft was installed or compromised. Screenshots are saved in the Evidence folder.
