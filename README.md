# Failed Login Detection — Splunk (Event ID 4625)

---

## What this is

A basic failed login detection using Windows Security Event ID 4625 inside Splunk.

The goal was not just to find failed authentication attempts, but to inspect how Windows actually logs failed logons, validate important fields, and turn the query into a usable Splunk alert.

This ended up being more useful as a telemetry validation exercise than just a simple detection rule.

---

## Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise 10.2.3 |
| OS | Windows VM |
| Log source | Windows Security Logs |
| Event ID | 4625 |
| Forwarder | Splunk Universal Forwarder |

---

## Detection query

```spl
index=* EventCode=4625
| table _time host Account_Name Source_Network_Address Logon_Type Failure_Reason
```

---

## What it detects

Windows generates Event ID 4625 whenever an authentication attempt fails.

In this lab, failed logins were intentionally triggered using invalid credentials against a fake account to generate telemetry for analysis.

The detection focuses on:
- failed authentication attempts
- account enumeration behavior
- brute force style activity
- invalid credential usage

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Brute Force | T1110 |
| Valid Accounts | T1078 |

---

## Test activity

Failed logins were generated using:

```cmd
runas /user:FakeUser cmd
```

Incorrect passwords were entered multiple times to create repeated 4625 events.

The events appeared successfully inside Splunk after querying EventCode 4625.

---

## Important fields observed

| Field | Purpose |
|------|---------|
| Account_Name | Username used during login attempt |
| Source_Network_Address | Source address of authentication |
| Logon_Type | Type of login attempt |
| Failure_Reason | Reason authentication failed |
| host | System generating the event |

---

## Interesting finding

The source address appeared as:

```text
::1
```

This is the IPv6 localhost loopback address, equivalent to:

```text
127.0.0.1
```

This indicated the authentication attempts originated locally from the machine itself rather than from an external source.

This is a good example of why raw event inspection matters before assuming attacker activity.

---

## Alert creation

The query was converted into a Splunk alert:

```text
Failed Login Threshold Detection
```

Trigger condition:

```text
Number of Results > 0
```

This was mainly done to practice operational detection workflow:
- query validation
- alert configuration
- event visibility
- SOC-style monitoring logic

---

## Issues encountered

### Field validation

Field names did not perfectly match expected documentation.

Raw event inspection was required to confirm:
- actual field names
- source address format
- authentication details
- logon type values

---

### Localhost confusion

Initially the source address looked unusual because it appeared as:

```text
::1
```

This turned out to be normal localhost IPv6 behavior rather than external attacker traffic.

Without inspecting the raw event carefully, this could easily be misunderstood.

---

## False positives

Common false positives for Event ID 4625 include:

- users mistyping passwords
- expired credentials
- service account authentication failures
- scheduled tasks using outdated credentials
- automated processes retrying authentication

Repeated failed logons from the same source become more interesting when combined with:
- frequency analysis
- multiple usernames
- unusual logon types
- remote source addresses

---

## Screenshots

| | |
|--|--|
| Query results | `screenshots/4625-query-results.png` |
| Raw event inspection | `screenshots/4625-raw-event.png` |
| Alert configuration | `screenshots/4625-saved-alert-config.png` |

---

## What I took away from this

The SPL itself was simple.

The useful part was learning how Windows authentication telemetry actually behaves:
- field validation
- localhost source interpretation
- failed login structures
- alert workflow configuration

This project reinforced the importance of inspecting raw telemetry before making assumptions about attacker behavior or field meanings.

---

