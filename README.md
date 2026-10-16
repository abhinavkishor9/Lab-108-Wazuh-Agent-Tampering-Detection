# Lab 108 — Wazuh Agent Tampering Detection
## Repository Description
Investigate Wazuh agent service-state changes, configuration integrity, and telemetry continuity using Windows service events, PowerShell, and the Wazuh manager. Validate agent connectivity, troubleshoot missing service events, preserve forensic evidence, and document detection limitations.
## Overview
The Wazuh agent provides endpoint telemetry to a centralized manager. If the agent is stopped, its startup configuration is modified, its configuration file is changed, or its communication is interrupted, the monitoring platform may lose visibility into endpoint activity.
This lab examines the Windows Wazuh agent service, its configuration file, local state information, Windows Service Control Manager events, and the agent's status on the Wazuh manager. A controlled service stop/start test was performed to investigate the evidence available when agent availability changes.
The investigation also examines a key detection challenge: local service activity, Windows event records, and Wazuh alerts are separate evidence sources. A service event may not appear in a filtered local search or in the Wazuh alerts index, and missing results require investigation before any conclusion is drawn.
## Lab Environment
| Component | Configuration |
|---|---|
| Endpoint | `DESKTOP-9MMM37V` |
| Operating system | Windows 11 Pro |
| Wazuh agent ID | `001` |
| Wazuh agent version | `4.12.0` |
| Wazuh manager | `192.168.203.129` |
| Agent IP | `192.168.203.1` |
| Agent service | `WazuhSvc` |
| Agent executable | `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` |
| Agent configuration | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Agent state file | `C:\Program Files (x86)\ossec-agent\wazuh-agent.state` |
| Evidence directory | `C:\WazuhAgentTamperingLab\Evidence` |
| Wazuh data view | `wazuh-alerts-*` |
## Investigation Objectives
- Record the baseline state and startup mode of the Wazuh agent service.
- Capture the agent configuration hash and state-file contents before and after a controlled service test.
- Verify endpoint connectivity to the Wazuh manager on TCP port 1514.
- Perform a controlled stop/start of the Wazuh agent and verify that the service returns to its expected state.
- Investigate Windows service events, particularly Event IDs 7036, 7040, and 7045.
- Compare local Windows evidence with the Wazuh manager's agent status and indexed event records.
- Investigate missing service events without assuming that a missing search result proves tampering or collection failure.
- Preserve collected evidence and generate a SHA-256 manifest.
## Investigation Scenario
A SOC analyst is validating the resilience and observability of the Wazuh agent on a Windows endpoint. The analyst records the current service state, configuration hash, agent state information, and active network connection before performing a controlled stop/start test.
Following the test, the Wazuh agent service is running with automatic startup. The configuration-hash snapshots have matching visible hash prefixes in the evidence manifest, while the before/after agent-state snapshot files have different manifest hashes. The complete state-file contents require comparison to establish precisely what changed.
The Wazuh manager reports agent `001` as Active and identifies the endpoint as Windows 11 Pro running Wazuh agent version 4.12.0. The endpoint also shows an established TCP connection from `192.168.203.1` to `192.168.203.129:1514`.
The local query for Windows service events 7036, 7040, and 7045 filtered to messages containing `Wazuh` or `OSSEC` returns no matching records during the controlled test window. Separately, a Wazuh event with System Event ID 7040 is observed, but the supplied event details do not identify the affected service. The analyst must not attribute this event to the Wazuh agent without examining the complete record.
## Windows Event IDs Investigated
| Event ID | Meaning | Investigation purpose |
|---|---|---|
| 7036 | Service entered a running or stopped state | Look for a service state transition |
| 7040 | Service start type changed | Identify changes to service startup configuration |
| 7045 | A service was installed | Identify service installation activity |
These are Windows System log events. They are distinct from Wazuh agent status information and should be interpreted using their full message, service name, timestamps, and record identifiers.
## Evidence Collected
| Artifact | Purpose |
|---|---|
| `investigation-start.txt` | Records investigation start time |
| `service-baseline.csv` | Records service state, startup mode, account, and executable path |
| `config-hash-before.txt` | Captures the configuration-file hash before the test |
| `config-hash-after.txt` | Captures the configuration-file hash after the test |
| `agent-state-before.txt` | Preserves agent state-file contents before the test |
| `agent-state-after.txt` | Preserves agent state-file contents after the test |
| `service-events-before.csv` | Stores matching service events from the baseline window, if found |
| `service-test-start.txt` | Records the start time used for the controlled service test |
| `service-events-during-test.csv` | Stores matching service events from the test window, if found |
| `evidence-hashes.csv` | Records SHA-256 hashes for the collected evidence files |
The directory and evidence filenames reflect the supplied PowerShell output. An artifact existing on disk does not by itself prove that it contains the expected records; its contents must be inspected.
## Findings
- The baseline reported `WazuhSvc` as Running with Automatic startup.
- The configuration file was located at `C:\Program Files (x86)\ossec-agent\ossec.conf`.
- The endpoint had an established TCP connection to `192.168.203.129` on remote port `1514`.
- The controlled stop/start commands completed without a displayed error, and the Wazuh service was Running afterward.
- The manifest displayed the same truncated SHA-256 prefix for `config-hash-before.txt` and `config-hash-after.txt`. The complete captured hash values should be compared to confirm equality.
- The manager reported agent `001` as Active, with Wazuh v4.12.0 on Windows 11 Pro.
- The local service-event query returned no matches after filtering messages for `Wazuh` or `OSSEC`.
- A Wazuh event with System Event ID 7040 and record ID `50916` was observed. The supplied fields do not establish which service was affected, so it cannot yet be attributed to the controlled test.
- The evidence manifest was generated for the collected files.
## Limitations
The supplied evidence does not establish that a local Event ID 7036 corresponding to the controlled Wazuh service stop/start was captured by the filtered query. The query filters by message text, so a non-matching display name or message could exclude an event even when the event ID is relevant.
The observed Wazuh Event ID 7040 lacks the service name and complete event message in the supplied extract. It must not be presented as proof that the Wazuh agent's startup type was modified.
The manager's Active status confirms that the agent was considered active at the time of the manager query. It does not independently prove uninterrupted connectivity throughout the service test.
Different hashes for `agent-state-before.txt` and `agent-state-after.txt` show that the saved evidence snapshots differ, but their contents must be compared to explain the difference. Matching visible hash prefixes for the configuration snapshots are not a substitute for comparing their complete SHA-256 values.
## Conclusion
The lab established baseline service and configuration evidence, confirmed an established connection to the manager, performed a controlled service stop/start, and verified that the agent returned to a Running state. The manager subsequently reported the agent as Active.
The main unresolved question is why the local service-event query did not return a matching event during the test and whether the observed Wazuh Event ID 7040 relates to the agent. Further analysis should inspect the full Windows event message, confirm the event timestamp and service name, and compare the complete before/after state and configuration snapshots.
## Key Learning
**A healthy service state, active manager status, and an established TCP connection are related but distinct observations.** A defensible investigation compares all three with timestamped event records before concluding that tampering occurred or that telemetry was lost.
