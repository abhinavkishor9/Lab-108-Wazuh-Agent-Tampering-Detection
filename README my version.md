# Lab-108-Wazuh-Agent-Tampering-Detection
## Overview
A Wazuh agent provides endpoint telemetry to the Wazuh manager. If the agent is stopped, its configuration is altered, its service settings are changed, or its installation is removed, monitoring coverage may be interrupted.
Agent service changes
Investigate Windows System Event ID 7036 for service state transitions, Event ID 7040 for startup-type changes, and Event ID 7045 for service installation.

Agent configuration integrity
Record the SHA-256 hash of the agent configuration file and compare it after the controlled test. A changed hash indicates a file-content difference, not necessarily malicious modification.

Agent connectivity
Compare the local agent status with its status on the manager. Wazuh tracks agent states such as Active, Disconnected, Pending, and Never connected. 

Important distinction: Wazuh's built-in anti-tampering feature prevents unauthorized agent removal but is supported only on Linux endpoints. This Windows lab focuses on detecting service and configuration changes using independent telemetry rather than claiming that the Windows agent has that protection enabled. 

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
## Lab Objectives
The objective of this lab is to investigate changes affecting the Wazuh agent service, validate agent configuration integrity, and evaluate whether endpoint and manager-side evidence provides sufficient visibility into service interruptions and potential tampering.
- **Establish the agent baseline:** Record the Wazuh agent service state, startup mode, executable path, and relevant configuration locations before performing controlled tests.
- **Validate configuration integrity:** Generate SHA-256 hashes of the agent configuration file before and after the test and compare the complete hash values to identify content changes.
- **Examine agent state information:** Preserve and compare the agent state snapshots to identify changes in connection status, timestamps, or other recorded fields.
- **Verify endpoint connectivity:** Examine the TCP connection to the Wazuh manager and document the connection state before and after the controlled service test.
- **Investigate service-state transitions:** Perform a controlled Wazuh agent stop/start test and examine Windows System Event ID 7036 for corresponding service state changes.
- **Analyze service configuration and installation events:** Investigate Event ID 7040 for service startup-type changes and Event ID 7045 for service installation activity, identifying the affected service from the complete event message.
- **Validate manager-side agent status:** Use the Wazuh manager to inspect the agent's reported status and compare it with endpoint service and connectivity observations.
- **Investigate missing service telemetry:** Examine why relevant Windows service events may not appear in local query results or the Wazuh alerts index, considering time ranges, message filters, event collection, and alerting rules.
- **Correlate endpoint and SIEM evidence:** Compare local event timestamps, event record IDs, service names, configuration hashes, and manager-side observations to assess whether the evidence supports a consistent timeline.
- **Preserve investigation artifacts:** Export relevant event records, retain configuration and state snapshots, and generate a SHA-256 evidence manifest for integrity checking.
- **Document detection limitations:** Distinguish confirmed service activity from unverified event correlations, unexplained snapshot differences, and potential telemetry gaps.
- **Develop a defensible conclusion:** Assess whether the collected evidence establishes a service interruption, configuration change, loss of monitoring visibility, or unauthorized tampering without treating these outcomes as equivalent.

### Expected Learning Outcome
Upon completing this lab, the investigator should be able to examine Wazuh agent service activity, validate configuration and state evidence, correlate Windows events with manager-side status, investigate telemetry gaps, and distinguish confirmed observations from hypotheses about agent tampering.## Investigation Scenario
A SOC analyst is validating the resilience and observability of the Wazuh agent on a Windows endpoint. The analyst records the current service state, configuration hash, agent state information, and active network connection before performing a controlled stop/start test.
Following the test, the Wazuh agent service is running with automatic startup. The configuration-hash snapshots have matching visible hash prefixes in the evidence manifest, while the before/after agent-state snapshot files have different manifest hashes. The complete state-file contents require comparison to establish precisely what changed.
The Wazuh manager reports agent `001` as Active and identifies the endpoint as Windows 11 Pro running Wazuh agent version 4.12.0. The endpoint also shows an established TCP connection from `192.168.203.1` to `192.168.203.129:1514`.
The local query for Windows service events 7036, 7040, and 7045 filtered to messages containing `Wazuh` or `OSSEC` returns no matching records during the controlled test window. Separately, a Wazuh event with System Event ID 7040 is observed, but the supplied event details do not identify the affected service. The analyst must not attribute this event to the Wazuh agent without examining the complete record.

## Lab Scenario
A SOC analyst is investigating whether changes to the Wazuh agent service could interrupt endpoint monitoring or reduce the visibility of security events. The investigation focuses on service-state transitions, configuration integrity, agent connectivity, and the consistency of evidence collected locally and reported by the Wazuh manager.
The analyst begins by recording the Windows service state, the SHA-256 hash of the agent configuration file, and the contents of the agent state file. An established TCP connection from the Windows endpoint to the Wazuh manager on port 1514 is also observed. These measurements provide a baseline for evaluating the agent's condition before and after a controlled service test.
The analyst then stops the `WazuhSvc` service, waits briefly, and starts it again. After the test, PowerShell reports that the service is running with automatic startup. The agent's configuration and state information are captured again, and the Wazuh manager reports agent `001` as Active. However, the saved state snapshots have different hashes, and the complete contents must be compared to determine what changed. The matching visible prefixes of the configuration-hash snapshots also require verification using their complete values.
During the investigation, the analyst searches Windows System events for service state changes, startup-type modifications, and service installations. The local query filtered for messages containing `Wazuh` or `OSSEC` returns no matching events during the test window. A separate Wazuh record with Event ID 7040 is observed, but the available evidence does not identify the affected service or establish that it corresponds to the controlled test.
The analyst must therefore determine whether the apparent gap results from the query's time range or message filter, missing local event records, or differences between event collection and alert indexing. The agent's Active status after the test is useful evidence of recovery, but it does not prove that monitoring remained uninterrupted throughout the service interruption.
### Investigation Questions
- What were the Wazuh agent's service state, startup mode, configuration hash, and connectivity status before the test?
- Did the controlled stop/start produce Windows Event ID 7036 records identifying `WazuhSvc`?
- What differences exist between the before-and-after agent state snapshots?
- Do the complete configuration hashes confirm that `ossec.conf` remained unchanged?
- Which service is identified in the observed Event ID 7040 record, and does its timestamp correspond to the test?
- Did the Wazuh manager report any change in agent status during or after the test?
- Why did the filtered local query return no matching service events, and what evidence is needed to distinguish a query limitation from a telemetry gap?
### Expected Outcome
The analyst should produce a documented sequence of the controlled service test, compare the before-and-after configuration and state evidence, and correlate relevant Windows events with the manager's agent status. The final assessment must distinguish confirmed service activity from unresolved event correlations and potential monitoring gaps, without claiming unauthorized tampering unless the evidence supports that conclusion.

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
