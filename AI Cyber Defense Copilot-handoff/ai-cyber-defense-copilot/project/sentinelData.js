export const analysts = [
  { id: 'a1', name: 'M. Alvarez', initials: 'MA', role: 'Senior SOC Analyst', load: 6, capacity: 8 },
  { id: 'a2', name: 'J. Okafor', initials: 'JO', role: 'Threat Hunter', load: 4, capacity: 8 },
  { id: 'a3', name: 'R. Chen', initials: 'RC', role: 'IR Lead', load: 7, capacity: 8 },
  { id: 'a4', name: 'S. Novak', initials: 'SN', role: 'SOC Analyst', load: 3, capacity: 8 },
];

export const cases = [
  { id: 'CASE-2049', title: 'SSH Brute Force Leading to Lateral Movement & Credential Phishing', severity: 'Critical', status: 'Active', assignee: 'M. Alvarez', priority: 'P1', risk: 88, tags: ['brute-force', 'phishing', 'lateral-movement'], created: '2026-07-18', updated: '2 min ago', evidenceCount: 4, findingsCount: 5 },
  { id: 'CASE-2048', title: 'Exposed RDP Endpoint on Legacy Finance Host', severity: 'High', status: 'Active', assignee: 'J. Okafor', priority: 'P2', risk: 71, tags: ['exposure', 'rdp'], created: '2026-07-17', updated: '38 min ago', evidenceCount: 2, findingsCount: 3 },
  { id: 'CASE-2047', title: 'Suspicious PowerShell Encoded Command on WEB-PROD-03', severity: 'High', status: 'Investigating', assignee: 'R. Chen', priority: 'P2', risk: 76, tags: ['powershell', 'defense-evasion'], created: '2026-07-16', updated: '1 hr ago', evidenceCount: 3, findingsCount: 4 },
  { id: 'CASE-2046', title: 'Phishing Campaign Targeting Finance Distribution List', severity: 'Medium', status: 'Active', assignee: 'S. Novak', priority: 'P3', risk: 54, tags: ['phishing', 'email'], created: '2026-07-15', updated: '3 hr ago', evidenceCount: 5, findingsCount: 2 },
  { id: 'CASE-2045', title: 'Anomalous Outbound DNS to Newly Registered Domain', severity: 'Medium', status: 'Investigating', assignee: 'M. Alvarez', priority: 'P3', risk: 48, tags: ['c2', 'dns'], created: '2026-07-14', updated: '5 hr ago', evidenceCount: 2, findingsCount: 2 },
  { id: 'CASE-2044', title: 'Nmap Scan Reveals Unpatched Apache Struts on DMZ Host', severity: 'High', status: 'Contained', assignee: 'J. Okafor', priority: 'P2', risk: 63, tags: ['vulnerability', 'exposure'], created: '2026-07-12', updated: '1 day ago', evidenceCount: 1, findingsCount: 3 },
  { id: 'CASE-2043', title: 'Credential Stuffing Attempts Against SSO Portal', severity: 'Low', status: 'Resolved', assignee: 'S. Novak', priority: 'P4', risk: 29, tags: ['credential-access'], created: '2026-07-10', updated: '2 days ago', evidenceCount: 2, findingsCount: 1 },
  { id: 'CASE-2042', title: 'Insider Data Exfiltration to Personal Cloud Storage', severity: 'Critical', status: 'Investigating', assignee: 'R. Chen', priority: 'P1', risk: 91, tags: ['exfiltration', 'insider'], created: '2026-07-09', updated: '2 days ago', evidenceCount: 6, findingsCount: 6 },
  { id: 'CASE-2041', title: 'Malicious Macro in Vendor Invoice Attachment', severity: 'Medium', status: 'Resolved', assignee: 'J. Okafor', priority: 'P3', risk: 41, tags: ['phishing', 'macro'], created: '2026-07-07', updated: '4 days ago', evidenceCount: 3, findingsCount: 2 },
  { id: 'CASE-2040', title: 'Unusual Service Account Login Outside Business Hours', severity: 'Low', status: 'Resolved', assignee: 'M. Alvarez', priority: 'P4', risk: 22, tags: ['discovery'], created: '2026-07-05', updated: '6 days ago', evidenceCount: 1, findingsCount: 1 },
];

export const primaryCase = cases[0];

export const evidenceItems = [
  { id: 'EV-1', name: 'ssh_auth.log', type: 'Log File', size: '4.2 MB', uploaded: '2026-07-18 09:14', parser: 'Syslog / SSH Auth Parser', status: 'Processed', findings: 3 },
  { id: 'EV-2', name: 'phishing_alert.eml', type: 'Email', size: '84 KB', uploaded: '2026-07-18 09:16', parser: 'Email Header + Body Parser', status: 'Processed', findings: 1 },
  { id: 'EV-3', name: 'nmap_scan_web-prod-03.xml', type: 'Nmap Scan', size: '212 KB', uploaded: '2026-07-18 09:21', parser: 'Nmap XML Parser', status: 'Processed', findings: 1 },
  { id: 'EV-4', name: 'edr_process_tree.json', type: 'EDR Export', size: '1.1 MB', uploaded: '2026-07-18 10:02', parser: 'EDR Process Tree Parser', status: 'Processing', findings: 0 },
];

export const iocs = [
  { id: 'ioc-1', type: 'IP', value: '203.0.113.44', role: 'C2 / Brute-force source', confidence: 94, threatScore: 91, severity: 'Critical', firstSeen: '2026-07-18 03:12', tags: ['tor-exit', 'known-scanner'] },
  { id: 'ioc-2', type: 'IP', value: '198.51.100.9', role: 'Reconnaissance scanner', confidence: 81, threatScore: 68, severity: 'High', firstSeen: '2026-07-17 22:40', tags: ['scanning'] },
  { id: 'ioc-3', type: 'Domain', value: 'secure-login-update.com', role: 'Phishing landing page', confidence: 96, threatScore: 93, severity: 'Critical', firstSeen: '2026-07-18 09:02', tags: ['typosquat', 'newly-registered'] },
  { id: 'ioc-4', type: 'URL', value: 'hxxps://secure-login-update.com/sso/verify', role: 'Credential harvesting link', confidence: 95, threatScore: 92, severity: 'Critical', firstSeen: '2026-07-18 09:03', tags: ['credential-harvest'] },
  { id: 'ioc-5', type: 'Hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4', role: 'Dropped payload (SHA-1)', confidence: 88, threatScore: 85, severity: 'High', firstSeen: '2026-07-18 10:04', tags: ['dropper'] },
  { id: 'ioc-6', type: 'Email', value: 'billing-support@evil-corp-mail.ru', role: 'Phishing sender', confidence: 90, threatScore: 87, severity: 'High', firstSeen: '2026-07-18 09:01', tags: ['spoofed-sender'] },
  { id: 'ioc-7', type: 'Process', value: 'powershell.exe -enc JAB...', role: 'Encoded execution', confidence: 79, threatScore: 74, severity: 'High', firstSeen: '2026-07-18 10:03', tags: ['living-off-the-land'] },
  { id: 'ioc-8', type: 'Registry Key', value: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', role: 'Persistence mechanism', confidence: 72, threatScore: 66, severity: 'Medium', firstSeen: '2026-07-18 10:05', tags: ['persistence'] },
  { id: 'ioc-9', type: 'IP', value: '10.20.4.31', role: 'Internal pivot host', confidence: 55, threatScore: 40, severity: 'Medium', firstSeen: '2026-07-18 10:10', tags: ['internal', 'lateral-movement'] },
];

export const mitreTechniques = [
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', ruleId: 'R-T1110-repeated-auth-failure', rationale: "Repeated username IOCs from a single source within a short window. Matched 7 indicator(s): username='admin', username='root', username='ubuntu', username='test', and 3 more.", confidence: 92, findings: ['F-1'], evidence: ['EV-1'] },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence', ruleId: 'R-T1078-successful-auth-after-failures', rationale: 'A successful authentication immediately followed a sustained brute-force window from the same source IP, indicating a compromised credential.', confidence: 87, findings: ['F-2'], evidence: ['EV-1'] },
  { id: 'T1021.004', name: 'Remote Services: SSH', tactic: 'Lateral Movement', ruleId: 'R-T1021-ssh-session-pivot', rationale: 'Authenticated SSH session originated a connection to an internal host (10.20.4.31) not previously observed in this environment.', confidence: 74, findings: ['F-3'], evidence: ['EV-1', 'EV-4'] },
  { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access', ruleId: 'R-T1566-phishing-link-and-sender', rationale: "Spoofed sender domain plus a credential-harvesting link co-occurring in a single message. Matched EMAIL IOC 'billing-support@evil-corp-mail.ru'.", confidence: 90, findings: ['F-4'], evidence: ['EV-2'] },
  { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution', ruleId: 'R-T1059-encoded-powershell', rationale: 'Base64-encoded PowerShell command line executed shortly after initial SSH access, consistent with a staged second-stage payload.', confidence: 81, findings: ['F-5'], evidence: ['EV-4'] },
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', ruleId: null, rationale: 'Dormant — gated behind LSASS-access telemetry not yet present in this case.', confidence: 0, findings: [], evidence: [] },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', ruleId: null, rationale: 'Dormant — requires an explicit scanning-behavior tag not yet set for this evidence set.', confidence: 0, findings: [], evidence: [] },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery', ruleId: null, rationale: 'Dormant — gated behind co-occurrence tag to avoid false-positive over-generalization.', confidence: 0, findings: [], evidence: [] },
];

export const mitreTactics = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];

export const findings = [
  { id: 'F-1', title: "Brute Force (T1110): username 'admin', 'root', 'ubuntu', 'test', and 3 more", severity: 'Critical', evidenceSummary: '312 failed SSH authentication attempts from 203.0.113.44 across 41 minutes.', severityRationale: 'Escalated to Critical: high attempt volume plus a subsequent successful login from the same source.' },
  { id: 'F-2', title: 'Valid Accounts (T1078): successful login for admin following brute-force window', severity: 'Critical', evidenceSummary: "Authentication succeeded for user 'admin' at 03:54:02, 41 minutes into the brute-force window.", severityRationale: 'Base severity High, escalated to Critical due to confirmed compromise indicator.' },
  { id: 'F-3', title: 'Remote Services (T1021.004): SSH pivot to internal host 10.20.4.31', severity: 'High', evidenceSummary: 'Post-compromise SSH session opened an outbound connection to a previously unseen internal host.', severityRationale: 'High: internal lateral movement confirmed, no data exfiltration confirmed yet.' },
  { id: 'F-4', title: "Phishing (T1566.001): spoofed sender 'billing-support@evil-corp-mail.ru'", severity: 'High', evidenceSummary: 'Email header spoofing plus a credential-harvesting link matching a newly registered domain.', severityRationale: 'High: credential harvest link confirmed live, no confirmed click yet.' },
  { id: 'F-5', title: 'Encoded PowerShell execution shortly after initial access', severity: 'Medium', evidenceSummary: 'Base64-encoded PowerShell invocation observed 9 minutes after SSH pivot.', severityRationale: 'Medium: execution confirmed, payload intent not yet fully decoded.' },
];

export const timelineEvents = [
  { id: 'tl-1', time: '2026-07-18 09:14:02', category: 'evidence', title: 'Evidence uploaded: ssh_auth.log', detail: 'SOC Analyst Agent began parsing 4.2 MB syslog export.' },
  { id: 'tl-2', time: '2026-07-18 09:14:38', category: 'ioc', title: 'IOC extraction complete', detail: '26 indicators extracted: 2 IPs, 1 domain, 1 URL, 1 hash, 1 email, 1 process, 1 registry key, and repeated usernames.' },
  { id: 'tl-3', time: '2026-07-18 09:15:10', category: 'finding', title: 'Finding generated: Brute Force (T1110)', detail: '312 failed authentication attempts from 203.0.113.44 across 41 minutes.' },
  { id: 'tl-4', time: '2026-07-18 09:15:41', category: 'mitre', title: 'MITRE mapping: T1110, T1078 applied', detail: 'Coordinator Agent mapped 2 techniques with rule-based rationale.' },
  { id: 'tl-5', time: '2026-07-18 09:16:20', category: 'evidence', title: 'Evidence uploaded: phishing_alert.eml', detail: 'Phishing Investigation Agent began header and body analysis.' },
  { id: 'tl-6', time: '2026-07-18 09:17:02', category: 'finding', title: 'Finding generated: Phishing (T1566.001)', detail: 'Spoofed sender and credential-harvesting link identified.' },
  { id: 'tl-7', time: '2026-07-18 09:21:44', category: 'evidence', title: 'Evidence uploaded: nmap_scan_web-prod-03.xml', detail: 'Vulnerability Assessment Agent parsed scan results.' },
  { id: 'tl-8', time: '2026-07-18 10:02:15', category: 'evidence', title: 'Evidence uploaded: edr_process_tree.json', detail: 'Processing in progress — SOC Analyst Agent.' },
  { id: 'tl-9', time: '2026-07-18 10:03:30', category: 'mitre', title: 'MITRE mapping: T1021.004, T1059.001 applied', detail: 'Lateral movement and PowerShell execution mapped from EDR telemetry.' },
  { id: 'tl-10', time: '2026-07-18 10:05:12', category: 'recommendation', title: 'Incident Response Plan generated', detail: 'Severity escalated to Critical — justification: brute-force volume + confirmed valid-account compromise.' },
  { id: 'tl-11', time: '2026-07-18 10:06:00', category: 'agent', title: 'Memory Agent: 2 similar past cases surfaced', detail: 'CASE-1988 and CASE-1873 shared IOC overlap and technique pattern.' },
];

export const agentDecisions = [
  { id: 'ad-1', agent: 'Coordinator Agent', decision: 'Routed evidence to SOC Analyst, Phishing Investigation, and Vulnerability Assessment agents in parallel.', confidence: 'High', time: '09:14:05' },
  { id: 'ad-2', agent: 'SOC Analyst Agent', decision: "Classified 203.0.113.44 as malicious (threat score 91) — escalated brute-force finding to Critical.", confidence: 'High', time: '09:15:08' },
  { id: 'ad-3', agent: 'Phishing Investigation Agent', decision: 'Identified sender-domain spoofing and a live credential-harvesting link; recommended immediate domain takedown request.', confidence: 'High', time: '09:16:55' },
  { id: 'ad-4', agent: 'MITRE Mapping Agent', decision: 'Applied require_co_occurrence gating — declined to map T1046/T1082 due to insufficient evidence, avoiding false positives.', confidence: 'Medium', time: '09:15:38' },
  { id: 'ad-5', agent: 'Memory Agent', decision: 'Surfaced 2 similar past cases (CASE-1988, CASE-1873) sharing IOC and technique overlap, informing containment priority.', confidence: 'Medium', time: '10:06:00' },
  { id: 'ad-6', agent: 'Incident Response Agent', decision: 'Escalated incident severity to Critical — justification: brute-force volume exceeded threshold and a valid-account compromise was confirmed.', confidence: 'High', time: '10:05:12' },
];

export const irPlan = {
  severity: 'Critical',
  justification: 'Base severity High (confirmed brute force) escalated to Critical because a successful authentication occurred from the same source within the attack window, confirming account compromise.',
  actions: [
    { category: 'Containment', text: 'Block network traffic from 4 malicious indicators: 203.0.113.44, 198.51.100.9, secure-login-update.com, and the associated URL.', priority: 'Immediate' },
    { category: 'Containment', text: "Disable and force credential reset for user 'admin' pending investigation.", priority: 'Immediate' },
    { category: 'Eradication', text: 'Remove persistence mechanism at HKLM\\...\\Run\\Updater on affected host.', priority: 'High' },
    { category: 'Eradication', text: 'Terminate and quarantine encoded PowerShell process and dropped payload (SHA-1 e3b0c44...).', priority: 'High' },
    { category: 'Recovery', text: 'Rotate SSH keys and enforce MFA on all externally reachable SSH endpoints.', priority: 'Medium' },
    { category: 'Lessons Learned', text: 'Review SSH exposure policy for WEB-PROD-03 and require bastion-only access going forward.', priority: 'Medium' },
  ],
};

export const reports = [
  { id: 'r-1', type: 'Executive', title: 'Executive Summary — CASE-2049', generated: '2026-07-18 10:12', pages: 3 },
  { id: 'r-2', type: 'Technical', title: 'Technical Investigation Report — CASE-2049', generated: '2026-07-18 10:14', pages: 11 },
  { id: 'r-3', type: 'Incident Response', title: 'Incident Response Report — CASE-2049', generated: '2026-07-18 10:15', pages: 6 },
];

export const threatIntelFeed = [
  { id: 'ti-1', title: 'Newly registered typosquat domains targeting SSO login flows', source: 'Internal Detection Engineering', severity: 'High', confidence: 88, time: '38 min ago' },
  { id: 'ti-2', title: 'Uptick in SSH brute-force sourced from ASN 64500 (bulletproof hosting)', source: 'Open Threat Exchange', severity: 'Critical', confidence: 93, time: '1 hr ago' },
  { id: 'ti-3', title: "Actor cluster 'SILENT FALCON' observed reusing PowerShell loader pattern", source: 'Vendor Feed — Managed Intel', severity: 'High', confidence: 79, time: '3 hr ago' },
  { id: 'ti-4', title: 'CVE-2026-31122 — Apache Struts RCE actively exploited in the wild', source: 'National Vulnerability Database', severity: 'Critical', confidence: 96, time: '5 hr ago' },
  { id: 'ti-5', title: 'Credential-stuffing tooling update lowers detection rate for legacy WAFs', source: 'Open Threat Exchange', severity: 'Medium', confidence: 71, time: '9 hr ago' },
];

export const threatActors = [
  { id: 'act-1', name: 'SILENT FALCON', motivation: 'Financial', sophistication: 'Advanced', confidence: 79, techniques: ['T1566.001', 'T1059.001', 'T1078'], targets: 'Financial services, SaaS' },
  { id: 'act-2', name: 'COBALT WRAITH', motivation: 'Espionage', sophistication: 'Advanced', confidence: 64, techniques: ['T1021.004', 'T1003'], targets: 'Government, critical infrastructure' },
  { id: 'act-3', name: 'GHOST LEDGER', motivation: 'Financial', sophistication: 'Intermediate', confidence: 55, techniques: ['T1110', 'T1078'], targets: 'Cryptocurrency exchanges' },
];

export const activityLog = [
  { id: 'al-1', actor: 'M. Alvarez', action: 'Assigned CASE-2049 to self', time: '09:14:00' },
  { id: 'al-2', actor: 'Coordinator Agent', action: 'Started multi-agent investigation', time: '09:14:05' },
  { id: 'al-3', actor: 'M. Alvarez', action: 'Added note: "Escalating — active compromise, notifying IR lead"', time: '09:18:22' },
  { id: 'al-4', actor: 'R. Chen', action: 'Joined case as IR Lead', time: '09:20:10' },
  { id: 'al-5', actor: 'Report Generator Agent', action: 'Generated Executive Summary', time: '10:12:00' },
];
