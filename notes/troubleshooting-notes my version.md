# Troubleshooting Notes
## 1. Local Service Event Query Returned No Matching Results
### Observed behavior
The local query searched System event IDs 7036, 7040, and 7045 and then retained only messages containing `Wazuh` or `OSSEC`. The result was:
`No matching Wazuh/OSSEC service events found in the test window.`
### Explanation
The output only establishes that no event passed both the event-ID/time filter and the message-text filter. A relevant service event could have been excluded if the message did not contain the specified terms, or if the event fell outside the recorded test window.
### Corrected investigation query
First, define the test timestamp and examine all candidate events without filtering by message:
```powershell
$LabPath = "C:\WazuhAgentTamperingLab\Evidence"
$TestStart = [datetime]::Parse(
    (Get-Content (Join-Path $LabPath "service-test-start.txt") -Raw)
)

Get-WinEvent -FilterHashtable @{
    LogName   = "System"
    Id        = 7036, 7040, 7045
    StartTime = $TestStart.AddMinutes(-2)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, RecordId, ProviderName, Message |
    Format-List
```
Inspect each message for the actual service name. Only after identifying a relevant event should it be filtered or grouped by service.
## 2. Wazuh Shows Event ID 7040, but the Local Filter Found Nothing
### Observed behavior
A Wazuh event was found with System Event ID 7040 and record ID `50916`, but the supplied excerpt did not include its full message or affected service name.
### Interpretation
Event ID 7040 represents a service startup-type change. The supplied test only stopped and started `WazuhSvc`; it did not intentionally change its startup mode. The event could be unrelated to the test.
### Troubleshooting
Run the unfiltered local service-event query above and inspect the complete Wazuh event JSON. Compare:
- The event timestamp and local timezone.
- The Windows event record ID.
- The service name and full message.
- Whether the event occurred during the test window.
Do not claim this event documents Wazuh service tampering unless the complete record supports that interpretation.
## 3. Verify the Test Timestamp
The script captured `$TestStart` before stopping the service, then saved that value after the service was started again. That design is valid because the variable retained the original timestamp.
If re-running any part of the query in a new PowerShell session, load the saved value again:
```powershell
$LabPath = "C:\WazuhAgentTamperingLab\Evidence"
$TestStart = [datetime]::Parse(
    (Get-Content (Join-Path $LabPath "service-test-start.txt") -Raw)
)
$TestStart
```
If the file is absent or malformed, define a new time range explicitly rather than passing a null value to `Get-WinEvent`.
## 4. Verify Wazuh Service State After the Test
The supplied output showed `WazuhSvc` as Running with Automatic startup.
Use this read-only command to verify the current state:
```powershell
Get-Service -Name WazuhSvc |
    Format-List Name, Status, StartType
```
If the service is stopped, document the error and investigate the service logs before making changes. Do not uninstall or re-enroll the agent simply to produce a test event.
## 5. Validate Agent Connectivity
The pre-test check returned an established connection to the manager:
```powershell
Get-NetTCPConnection -RemotePort 1514 -State Established -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
    Format-Table -AutoSize
```
The observed connection was from `192.168.203.1` to `192.168.203.129:1514`.
If no connection appears later, check the service state, the manager address, the current time window, and agent logs. A single empty TCP query does not independently prove that the agent was tampered with.
## 6. Compare the Configuration Hashes Correctly
The manifest displayed the same truncated hash prefix for `config-hash-before.txt` and `config-hash-after.txt`. The complete recorded values should be compared directly:
```powershell
$LabPath = "C:\WazuhAgentTamperingLab\Evidence"

Get-Content (Join-Path $LabPath "config-hash-before.txt")
Get-Content (Join-Path $LabPath "config-hash-after.txt")
```
If the complete hashes match, the configuration file content did not change between the two measurements. If they differ, inspect the file's timestamps and contents before assigning a cause.
## 7. Compare Agent State Snapshots
The evidence manifest displayed different hashes for the before/after state snapshot files. Inspect their contents:
```powershell
$LabPath = "C:\WazuhAgentTamperingLab\Evidence"

Write-Host "=== State before ==="
Get-Content (Join-Path $LabPath "agent-state-before.txt")

Write-Host "`n=== State after ==="
Get-Content (Join-Path $LabPath "agent-state-after.txt")
```
State files can contain counters, timestamps, and status information that change during normal operation. Do not treat a changed hash as proof of malicious modification without identifying the changed fields.
## 8. Wazuh Manager Reports Agent Active
The manager-side `agent_control -i 001` output reported the agent as Active.
This establishes the manager's reported status at the time of the query. It does not prove that the agent remained connected throughout the stop/start test. Compare the manager's last keep-alive data with the test timeline and relevant logs.
## 9. Understand the Service Event IDs
| Event ID | Meaning | Evidence required |
|---|---|---|
| 7036 | Service entered a running or stopped state | Full message and correct service name |
| 7040 | Service startup type changed | Full message identifying the service and previous/new startup mode |
| 7045 | Service installed | Service name, file path, install time, and context |
Do not assume that all three IDs must appear for a simple service stop/start. Event 7040 is not expected unless the service's startup type changes, and Event 7045 is not expected unless a service is installed.
## 10. Evidence Hashing
The current evidence manifest is `evidence-hashes.csv`. If you add or alter evidence files, regenerate it:
```powershell
$LabPath = "C:\WazuhAgentTamperingLab\Evidence"
$HashFile = Join-Path $LabPath "evidence-hashes.csv"

Get-ChildItem -LiteralPath $LabPath -File |
    Where-Object { $_.FullName -ne $HashFile } |
    Get-FileHash -Algorithm SHA256 |
    Select-Object Path, Algorithm, Hash |
    Export-Csv -LiteralPath $HashFile -NoTypeInformation

Import-Csv -LiteralPath $HashFile |
    Format-Table -AutoSize
```
Save a copy of an earlier manifest separately if historical comparisons are important.
