# Example Case 01 — SSH Brute Force + Coordinated Phishing

**Status:** Narrative walkthrough only — the Investigation Workspace this
would run through doesn't exist yet (Milestone M6, `docs/roadmap.md`). This
document describes the *intended* end-to-end behavior using real fixtures
from `data/sample_evidence/`, and will be replaced with an actual generated
case export once the platform can produce one.

## Evidence uploaded to this case

| File | Evidence type |
|---|---|
| `data/sample_evidence/ssh_auth.log` | Server log |
| `data/sample_evidence/windows_security_events.csv` | Server log (Windows) |
| `data/sample_evidence/apache_access.log` | Web server log |
| `data/sample_evidence/phishing_sample_01.eml` | Phishing email |

## Expected narrative

1. **SOC Analyst Agent** processes `ssh_auth.log` and flags a burst of 12
   failed logins from `203.0.113.44` against `admin`/`root`/service accounts,
   followed by a successful login as `root` — classified **High** severity.

2. **MITRE Mapping Agent** maps this to **T1110 (Brute Force)** under the
   Credential Access tactic, and — once `windows_security_events.csv` shows
   the same source IP creating a new local account (`hacker`) and adding it
   to Administrators — additionally maps to **T1136 (Create Account)** and
   **T1098 (Account Manipulation)** under Persistence/Privilege Escalation.

3. **Threat Hunting Agent**, given both logs, identifies `203.0.113.44` as
   the coordinating IOC across systems and flags the WordPress login
   brute-force attempts and SQL-injection probe visible in
   `apache_access.log` as *related reconnaissance/exploitation activity from
   the same actor infrastructure*, not a separate incident.

4. **Phishing Investigation Agent**, given `phishing_sample_01.eml`
   separately, scores it in the 80s/100 (Critical) — spoofed Amazon sender
   domain (`amaz0n-security-verify.xyz`), urgency language, credential-
   harvesting link with a lookalike domain — and recommends blocking the
   sender domain and notifying the targeted user.

5. **Coordinator** correlates across evidence: no shared IOC between the
   phishing email and the SSH/web logs in this fixture set (they're
   deliberately separate threads), so the case timeline shows two distinct
   attack narratives rather than a false merge — demonstrating that
   correlation only asserts a link when evidence actually supports one.

6. **Incident Response Agent** produces a combined plan: contain
   (`203.0.113.44` blocked, `hacker` account disabled, compromised `root`
   password rotated) and separately, block the phishing sender domain and
   force a password reset for the targeted mailbox user.

7. **Report Generator Agent** produces one executive PDF covering both
   threads under this single case, each with its own MITRE mapping and
   remediation section.

## Why this case is a good fixture

It exercises: multi-evidence-type ingestion in one case, MITRE mapping across
two different log formats, IOC correlation *and* correct non-correlation
(the phishing thread should NOT be force-merged with the brute-force thread),
and a combined incident response plan spanning unrelated attack vectors —
the exact scenario `docs/adr/0001-layered-case-centric-architecture.md`
justifies the case-centric design for.
