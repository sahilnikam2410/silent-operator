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

| ID | Technique | Tactic | Status |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | detected |
| T1059 | Command & Scripting Interpreter | Execution | detected |
| T1046 | Network Service Discovery | Discovery | detected |
| T1190 | Exploit Public-Facing Application | Initial Access | assessed |
| T1071.001 | Application Layer Protocol: Web | Command & Control | research |
| T1566 | Phishing | Initial Access | detected |

`detected` = telemetry surfaced it and an alert fired · `assessed` = exercised
offensively, findings documented · `research` = analysed and turned into
detection logic. The live table with the full run/signal columns is at
<https://hackwithsahil.vercel.app/work/silent-operator>.

## Rules written

Two rules, currently **draft — written but not yet validated in the lab**.
The status badge on the case study says the same; it flips to validated once
the rule has actually fired against a controlled brute-force run.

**Wazuh — brute force on Windows logon, then contain**

```xml
<group name="local,authentication_failures,">
  <!-- 4625: an account failed to log on -->
  <rule id="100210" level="5">
    <if_sid>60122</if_sid>
    <description>Windows logon failure</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- six failures from one source inside two minutes -->
  <rule id="100211" level="10" frequency="6" timeframe="120">
    <if_matched_sid>100210</if_matched_sid>
    <same_source_ip />
    <description>Brute force: 6 failed logons from $(srcip) in 120s</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- a success straight after the burst is the one to wake up for -->
  <rule id="100212" level="12">
    <if_sid>60106</if_sid>
    <if_matched_sid>100211</if_matched_sid>
    <same_source_ip />
    <description>Brute force succeeded from $(srcip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>
```

Level 10 fires active response; level 12 is the page-worthy one, because a
success following a burst is the difference between noise and a compromise.
**False positives to tune out:** service accounts with stale cached
credentials, and password managers retrying after a change — both produce
failure bursts without an attacker.

**Same detection as Sigma** (portable to Splunk or Elastic):

```yaml
title: Windows brute force followed by success
status: experimental
logsource:
  product: windows
  service: security
detection:
  failures:
    EventID: 4625
  success:
    EventID: 4624
  timeframe: 2m
  condition: failures | count() by IpAddress > 5 and success
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## Scope

Every host in this lab is mine, on host-only networking, with no route to any
third-party system. No live targets, no credential material, no real hostnames.

## Rebuild it

<!-- TODO: setup steps, or a link to your lab-build video -->

---

## Part of a portfolio

The portfolio ties every project to the MITRE ATT&CK technique it covers:
**https://hackwithsahil.vercel.app**
