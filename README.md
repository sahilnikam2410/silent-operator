# The Silent Operator

SOC detection and red-team simulation lab. Attacks are run against hosts I own,
mapped to MITRE ATT&CK before execution, then hunted from the defender side to
find out what the stack actually caught.

Final-year project, 2025–2026.

## Environment

| Component | Role |
|---|---|
| Wazuh manager + indexer | SIEM, alert rules, active response |
| Wazuh agents | Windows 10 and Linux endpoints |
| Sysmon | Windows process/network telemetry |
| Kali Linux | Attacker host |
| VirtualBox | Isolated host-only networking |

## Method

1. Build the stack: manager, agents on every endpoint, Sysmon and system logs
   forwarded into centralised dashboards.
2. Pick a technique and write down its ATT&CK ID **and the telemetry it should
   produce** before running it.
3. Execute it against the lab, one technique at a time.
4. Hunt from the defender side: log correlation, custom alert rules, triage.
5. Record the outcome honestly — fired, or gap.
6. For every gap: write the rule, re-run the technique, confirm it fires.

## Coverage

<!-- TODO: paste your real per-technique table here. Columns:
     ATT&CK ID | technique | what you ran | what fired | outcome -->

| ID | Technique | Outcome |
|---|---|---|
| T1059 | Command & Scripting Interpreter | detected — Sysmon process creation correlated in Wazuh |

## Rules written

<!-- TODO: one code block per rule you authored. Wazuh XML, Sigma, or Splunk SPL.
     This is the part employers read. Include what triggers it and the false
     positives you had to tune out. -->

## Scope

Every host in this lab is mine, on host-only networking, with no route to any
third-party system. No live targets, no credential material, no real hostnames.

## Rebuild it

<!-- TODO: setup steps, or a link to your lab-build video -->
