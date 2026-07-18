# pages — Streamlit Multi-Page Routes

One file per page, numeric-prefixed for Streamlit's sidebar ordering
(`1_Case_Dashboard.py`, `2_New_Investigation.py`, `3_Evidence_Explorer.py`,
`4_Threat_Timeline.py`, `5_MITRE_Map.py`, `6_AI_Analyst_Chat.py`,
`7_Executive_Reports.py`, `8_Settings.py`). Each page imports and calls
`core/services` functions only — no direct DB/agent access from a page.
