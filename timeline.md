
# Investigation Timeline — Lab 27: Threat Intelligence + Endpoint Investigation

> Timestamps and query counts below reflect the supplied investigation results. Exact execution times for individual queries were not provided, so query order is used where a timestamp is unavailable.

| Sequence | Timestamp / Time Reference | Activity | Observation | Assessment |
|---|---|---|---|---|
| 1 | Initial baseline check | Queried process-creation and network events using event codes `1` and `3` | One document returned | A process-creation record was available, but the selected process and network fields were empty or unavailable |
| 2 | Subsequent query | Queried network connections using event code `3` | Zero documents returned | No matching network events were found in that query |
| 3 | Subsequent query | Summarized documents by `event.code` | 10 documents processed: one each for `2`, `16384`, and `16394`; seven with null event code | The searched data contained limited and incomplete event-code coverage |
| 4 | Subsequent query | Filtered on `event.provider == "Microsoft-Windows-Sysmon"` | Zero documents returned | The expected provider value was not found under the filter |
| 5 | Subsequent query | Queried process-creation events with selected process fields | Zero documents returned | Results were inconsistent with the earlier combined query |
| 6 | Subsequent query | Queried common command interpreters and script hosts | Zero documents returned | No documents matched the process-specific filter |
| 7 | 2026-10-16 06:06:55.434 | Timestamp shown in the single returned document | Host `desktop-9mmm37v`; event code `1` | Process-creation event observed, but usable process context was not available in the selected fields |
| 8 | Final assessment | Reviewed telemetry visibility and correlation limitations | No verified indicator match established | Investigation remained inconclusive |

## Current Status

**Inconclusive — additional telemetry validation required.**

The investigation did not establish a threat-intelligence match or confirm endpoint compromise. The next phase is to validate the time range, inspect the raw process-creation document, confirm field mappings, and determine whether Sysmon network events exist locally and are being ingested into Elastic.
