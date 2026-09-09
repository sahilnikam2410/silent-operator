# The Silent Operator

SOC detection and red-team simulation lab. Attacks are run against hosts I own,
mapped to MITRE ATT&CK before execution, then hunted from the defender side to
find out what the stack actually caught.

Final-year project, 2025–2026.

## Environment

| Component | Role |
|---|---|
| Wazuh manager + indexer | SIEM, alert rules, active response |
| Wazuh agents | Windows and Linux endpoints |
| Sysmon | Windows process/network telemetry |
| Kali Linux | Attacker host |
| Type-2 hypervisor | Isolated lab networking |

## Method

1. Build the stack: manager, agents, Sysmon and system logs forwarded into centralised dashboards.
2. Map each technique to its MITRE ATT&CK ID and expected telemetry before execution.
3. Execute controlled attacks against owned lab hosts, one technique at a time.
4. Hunt from the defender side: log correlation, custom alert rules and triage.
5. Record the outcome honestly — fired, or gap.
6. For gaps: write the rule, re-run the technique and confirm it fires.

## Coverage

| ID | Technique | Tactic | Status |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | **validated in lab** |
| T1059 | Command & Scripting Interpreter | Execution | detected |
| T1046 | Network Service Discovery | Discovery | detected |
| T1190 | Exploit Public-Facing Application | Initial Access | assessed |
| T1071.001 | Application Layer Protocol: Web | Command & Control | research |
| T1566 | Phishing | Initial Access | detected |

`validated in lab` means the custom detection fired during a controlled run and the resulting Wazuh event was captured as evidence.

## Rule validated in the lab

**Wazuh — Windows brute-force detection**

The deployed rule that fired on `WIN-SERVER-2022` is **rule 100211, level 12**. It correlates repeated Windows logon-failure events (Wazuh rule `60122`) and fires after five matches **from the same source** within 60 seconds.

`same_source_ip` is the load-bearing line. Without it the rule counts five
failures from any mix of sources, so five different machines each failing once
would raise a brute-force alert — a different detection with a much worse
false-positive rate.

```xml
<group name="authentication_failures,windows,">
  <rule id="100211" level="12" frequency="5" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <same_source_ip />
    <description>Brute-force attack detected - multiple Windows logon failures</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,brute_force,windows,</group>
  </rule>
</group>
```

**Validation receipt:** Wazuh Threat Hunting captured rule `100211` at **level 12** on `WIN-SERVER-2022` at approximately **21:39 on 5 Sep 2026**, preceded by multiple `60122` logon-failure events. The evidence image is `public/artifacts/bruteforce-100211.png`.

**Provenance of the XML above:** the level and the base rule are read
directly off the capture — `100211` at level 12 on `WIN-SERVER-2022` at
21:39:08 on 5 Sep 2026, preceded by four `60122` logon failures at level 5.
The `frequency` and `timeframe` values come from the lab notes and cannot be
confirmed: a dashboard shows what fired, not the rule that fired it, and the
lab has since been decommissioned. Treat those two numbers as a starting
point to tune rather than a measurement.

## The chain as designed — written, never validated

The rule above is what the manager was actually running on 5 Sep 2026. It is
not the rule this project set out to build. The intended detection was a
three-stage chain, and it never got a validated run against it:

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

`100212` is the one worth having. A burst of failures is noise until one of
them succeeds; the success straight after the burst is the difference between
someone knocking and someone inside. Neither `100210` nor `100212` appears
anywhere in the capture, so neither has ever been observed firing.

**Warning for anyone rebuilding from this:** `100211` means two different
things across these two blocks — level 12 chaining off `60122` in what ran,
level 10 chaining off `100210` in what was designed. Deploy the designed
chain over a manager holding the other and the id collides. Renumber before
loading it.

**False positives to tune:** service accounts with stale cached credentials and password managers retrying after a password change can create legitimate failure bursts.

## Sigma equivalent

```yaml
title: Windows brute force
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 60s
  condition: selection | count() by IpAddress >= 5
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## Scope

Every host in this lab is mine and runs inside an isolated lab environment. No live third-party targets, credential material or real-world systems are used.

## Rebuild it

Everything runs on one machine under a type-2 hypervisor, on a host-only
network with no route out. Build order matters — the manager has to be
listening before an agent can enrol, and telemetry has to be proven before
any result about it means anything.

1. **Network first.** Create the host-only network and put every VM on it.
   No NAT adapter. The lab must not be able to reach the internet, the host's
   LAN, or anything it does not own.
2. **Wazuh manager and indexer** on the Linux server VM. Confirm the
   dashboard loads before touching anything else.
3. **Agents** on the Windows and Linux endpoints, enrolled against the
   manager's host-only address. Each should read *active* in the dashboard.
4. **Sysmon on Windows**, with a config that logs process creation and
   network connections, and the Wazuh agent pointed at the Sysmon channel.
   Skip this and process telemetry never reaches the manager — which looks
   identical to a detection gap.
5. **Prove ingestion before attacking.** Generate one known event — a failed
   logon does it — and find it in the dashboard. Every "gap" recorded later
   is only meaningful once the pipeline is known to work.
6. **Kali** on the same host-only network, last.

Then run the loop in [Method](#method): map the technique, execute it, hunt
it, and write the rule if nothing fired.

**Versions and the Sysmon configuration are not recorded for this lab.** It
has been decommissioned and the config did not survive it, so these steps are
followable rather than reproducible — a reader can rebuild the same shape, not
the same environment.

A separate SOC lab of mine ran Sysmon 15.x with a SwiftOnSecurity-derived
configuration. That is deliberately not copied in here: it was a different
environment with a different collector, and transferring its details would
turn a gap into a quiet fabrication. If your own build needs a starting point,
that configuration is a good public one — but it is a recommendation, not a
record of what ran here.

---

## Part of a portfolio

The portfolio ties every project to the MITRE ATT&CK technique it covers:
**https://hackwithsahil.vercel.app**
