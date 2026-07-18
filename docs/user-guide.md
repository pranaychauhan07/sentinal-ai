# User Guide

*This guide describes the intended analyst workflow. Screens referenced here
are implemented progressively per `docs/roadmap.md` — features not yet built
are marked accordingly.*

## Starting an investigation

1. Open the **Landing Dashboard** — shows open case count, this week's
   findings, and a severity breakdown at a glance.
2. Click **New Investigation** to create a `Case`, or select an existing one
   from **Case Management** to continue work.
3. In the case's **Investigation Workspace**, upload evidence: a firewall/SSH
   log, a phishing `.eml`/`.txt`, an Nmap/Nessus/OpenVAS report, source code,
   or a free-text incident note. You can upload more than one type into the
   same case — this is the point of the case-centric design (see
   `context/01_blueprint.md` §1).

## What happens after upload

The Coordinator automatically classifies each evidence item and routes it to
the right specialist agent(s) — you don't have to tell it which module to
run. Watch the **Investigation Trail** panel for each agent's live
Thought → Action → Observation reasoning as it works.

## Reading findings

The **Findings** tab lists every result with a severity badge and a plain-
language explanation. Click any finding to see:
- The MITRE ATT&CK technique it maps to (if applicable) — see `docs/mitre.md`
- Its contribution to the overall case risk score
- A recommended action

## Threat Timeline and MITRE Map

The **Threat Timeline** tab reconstructs all evidence chronologically across
the whole case — e.g. a phishing email received, followed by a failed login
spike, followed by a suspicious outbound connection — so you can see the
attack story, not just a list of disconnected findings.

The **MITRE Map** tab shows a heatmap of which ATT&CK tactics/techniques this
case touched.

## Getting an Incident Response plan

Once a case reaches meaningful severity (or on request), open the **IR Plan**
tab for a NIST SP 800-61-structured containment/eradication/recovery/lessons-
learned plan synthesized from every finding in the case — not just the most
recent one.

## Generating a report

From **Executive Reports**, generate either a single-module report or a
full-case executive summary as a downloadable PDF, previewable in-app first.

## Asking the AI Analyst Chat

Use the case-scoped chat to ask follow-up questions ("why was finding #4
scored High?", "summarize this case for my manager") — answers are grounded
in this case's actual findings, not generic chatbot output.

## A note on trust

Every risk score and CVSS value you see is computed by deterministic code
(`core/tools/scoring.py`, `core/knowledge/cvss_calculator.py`), not LLM
arithmetic — the LLM explains and contextualizes, it doesn't do the math. The
Copilot recommends actions; a human always approves before anything is
marked as executed (see `core/security/approval_gate.py`).
