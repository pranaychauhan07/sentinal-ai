# MITRE ATT&CK in Cyber Defense Copilot

## What it is

MITRE ATT&CK is a public, structured knowledge base of real-world adversary
tactics and techniques (e.g., **T1110 = Brute Force**), maintained by MITRE.
It organizes attacker behavior into **tactics** (the "why" — e.g. Credential
Access) and **techniques** (the "how" — e.g. Brute Force under that tactic).

## Why it exists

Without a shared taxonomy, every analyst describes the same attack
differently ("weird login activity" vs. "credential stuffing" vs. "brute
force attempt"). ATT&CK gives the whole security industry — vendors,
analysts, threat intel feeds — one vocabulary, so a finding is portable
across tools and comparable across incidents.

## Where this project uses it

Every finding produced by the SOC Analyst Agent, Threat Hunting Agent, and
Incident Response Agent that describes attacker *behavior* (as opposed to a
static vulnerability, which is CVSS's job — see `docs/owasp.md` for the
vulnerability side) gets passed to the **MITRE Mapping Agent**
(`core/agents/mitre_agent.py`), which maps it to a technique ID with tactic
and confidence, backed by the local reference dataset in
`core/knowledge/mitre_attack.json`.

## Practical example

A log shows 40 failed SSH logins from one IP in two minutes, followed by one
success. The SOC Analyst Agent's finding — "repeated failed logins followed
by success from 203.0.113.4" — is handed to the MITRE Agent, which returns:

```
Technique: T1110 (Brute Force)
Tactic:    Credential Access
Confidence: High
```

This is what turns a raw observation into the same language a real SOC
ticket, a SIEM correlation rule, and a threat intel report would all use.

## Design rule

If the MITRE Agent cannot map a finding with reasonable confidence, it
returns **"unmapped"** rather than forcing a low-confidence guess into a
report — see `docs/agent-design.md` point 6 and blueprint §7 (MITRE Mapping
Agent — Failure handling).
