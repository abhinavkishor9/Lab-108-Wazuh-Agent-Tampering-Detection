# Lab 108 — Wazuh Agent Tampering Detection Notes
## 1. Configuration Integrity
The configuration file was hashed before and after the test using `Get-FileHash -Algorithm SHA256`.
The evidence manifest displayed the same visible hash prefix for the files `config-hash-before.txt` and `config-hash-after.txt`:
`9ED902B494060371EEF6D8CE8DE5F42F28E6A32F782D9B5D1...`
The manifest output truncated the full digest, so the complete values in both snapshot files should be compared before formally recording them as identical.
If the full configuration hashes match, that supports the conclusion that the `ossec.conf` content did not change between the two measurements. It does not rule out service stoppage, connectivity interruption, or other forms of agent tampering.
## 2. Agent State Snapshots
The lab preserved:
- `agent-state-before.txt`
- `agent-state-after.txt`
The evidence manifest displayed different SHA-256 values for these two snapshot files. This establishes that the saved snapshot files are not byte-for-byte identical, but it does not show which agent-state field changed.
The original state-file contents must be compared to determine whether differences reflect ordinary counters, timestamps, connection status, or something else. Do not characterize the differences as tampering without examining the contents.
## 3. Network Connectivity
The pre-test PowerShell output showed an established TCP connection:
| Field | Value |
|---|---|
| Local address | `192.168.203.1` |
| Local port | `7326` |
| Remote address | `192.168.203.129` |
| Remote port | `1514` |
| State | Established |
This provides evidence that the endpoint had an established connection to the Wazuh manager at the time of the check. It does not independently prove that no interruption occurred during the service stop/start.
## 4. Controlled Service Test
The test captured `$TestStart`, stopped `WazuhSvc`, waited 10 seconds, started the service again, waited another 10 seconds, and recorded the test-start timestamp for subsequent queries.
The commands returned to the prompt without a displayed error. The subsequent service check reported:
| Field | Result |
|---|---|
| Service | `WazuhSvc` |
| State | Running |
| Startup mode | Automatic |
This confirms the final reported service state after the test. It does not, by itself, establish that all intended Windows service events were recorded or forwarded to the manager.
## 5. Local Windows Service Event Search
The local query searched Windows System events 7036, 7040, and 7045 within the test window and filtered messages using:
`$_.Message -match "Wazuh|OSSEC"`
The result was:
`No matching Wazuh/OSSEC service events found in the test window.`
The query therefore did not return service events whose messages matched the specified text filter. It does not prove that the System log contains no relevant service activity; the event may have been outside the window, used a different service display name, or been excluded by the message filter.
The `service-events-before.csv` export was also created conditionally, so its presence should not be treated as proof that it contains matching records.
## 6. Wazuh Manager Agent Status
The manager-side `agent_control -i 001` output reported:
| Field | Observed value |
|---|---|
| Agent ID | `001` |
| Agent name | `DESKTOP-9MMM37V` |
| Reported status | Active |
| Operating system | Microsoft Windows 11 Pro |
| Client version | Wazuh v4.12.0 |
| IP address field | `any` |
| Syscheck last started | Fri Oct 16 06:39:20 2026 |
| Syscheck last ended | Fri Oct 16 06:40:14 2026 |
The output also included configuration and shared-file hashes and a last keep-alive value. The output's Active status establishes the manager's reported state when queried; it does not establish uninterrupted communication across the entire test.
## 7. Wazuh Event ID 7040
A Wazuh event with the following fields was observed:
| Field | Value |
|---|---|
| Channel | `System` |
| Computer | `DESKTOP-9MMM37V` |
| Event ID | `7040` |
| Event record ID | `50916` |
| Event source | `Service Control Manager` |
The supplied extract does not show the event's timestamp, service name, or full message. Windows Event ID 7040 represents a service startup-type change, but the evidence does not establish that the Wazuh service was the affected service.
The controlled test stopped and started `WazuhSvc`; it did not intentionally modify its startup type. Therefore, do not attribute Event ID 7040 to this test until the full event confirms the service name and message.
## 8. Evidence Hashing
The manifest `evidence-hashes.csv` was generated after evidence collection. It includes hashes of the before/after state snapshots, before/after configuration-hash captures, service baseline, investigation start time, and service test timestamp.
Some digest values were truncated in the displayed PowerShell table. The complete values can be inspected directly from `evidence-hashes.csv`. A manifest provides integrity-checking values for the collected files but does not independently establish authenticity, completeness, or causal attribution.
## 9. Findings
### Confirmed
- `WazuhSvc` was Running with Automatic startup in the baseline and after the controlled test.
- The endpoint had an established TCP connection to the Wazuh manager on port 1514 during the pre-test check.
- The manager reported agent `001` as Active.
- The configuration-hash snapshot files had matching visible hash prefixes in the manifest.
- The controlled stop/start command sequence completed without a displayed error.
- A Wazuh System Event ID 7040 record was visible.
- The evidence hash manifest was generated.
### Not established
- Whether the full before/after configuration hashes are identical.
- The exact differences between the agent state snapshots.
- A local Event ID 7036 record tied to the controlled service stop/start.
- Whether Event ID 7040 refers to the Wazuh agent service.
- Whether a monitoring gap was observed by the Wazuh manager during the test.
- Any unauthorized tampering.
