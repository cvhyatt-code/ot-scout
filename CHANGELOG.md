# OT Scout changelog

All notable changes to the passive assessment prototype. Versions are shown in the page header, browser tab and the startup line printed by `run.py`.

## v0.7.0 — 2026-09-05
- Capture throughput: frames are now written to the database in batches (one transaction per 200 frames or 250 ms) instead of one connection-and-commit per packet. Measured on a synthetic 100-device mix: 1,046 → 12,800 packets/second on this machine; the parser itself does ~130,000/s, so the database is still the ceiling, but it is now a ceiling most SPAN ports sit under. PCAP import batches the same way.
- Dropped-frame accounting: the capture reads the socket's own PACKET_STATISTICS every second and accumulates kernel drops — frames the OS discarded because the collector was too slow. Shown live on the Collect tab (in red, with what to do about it), stored per session, printed in the sessions table, in the report's coverage section (an amber callout when any session dropped frames, since the inventory for that session is incomplete in an unknown way) and in the evidence manifest. Previously a struggling laptop would have reported "mirror visibility" with no hint it missed anything.
- Raw PCAP saved for every live capture by default (checkbox on the Collect tab), classic libpcap format under data/captures/, one file per session named by session, collection point and time. It is the evidence of record and it lets a capture be re-run through a later build with better decoders. Nothing about capture changed on the wire — this is a file write of frames already in memory.
- Evidence package: one button on the Report tab produces a zip with the assessment JSON, the Word report, every CSV and the diagram, the raw PCAP of every session in the data set, a human-readable MANIFEST.txt (tool version, data set, every session with frames/recorded/dropped, every file with its purpose) and a SHA256SUMS file — verify later with `sha256sum -c SHA256SUMS`. This is what to keep with the engagement record and what to hand over when a result is challenged.
- Sessions table (UI and report) shows frames read vs recorded, dropped, and whether the PCAP was retained.

## v0.6.1 — 2026-09-05
- Report: new "OPC UA endpoints and sessions" section under Communications — one table of servers (endpoint, application/product, security modes, policies, user tokens, with None/Anonymous in red and a Review flag) and one of clients (application, which server it connects to, how it authenticated, which channel policy it used).
- Report: the passive-fingerprint table now uses readable labels ("OPC UA security policies offered", "CIP device type", "S7 order number") instead of internal field names, keeps only the best claim per field/value per asset instead of one row per evidence source, orders role/manufacturer/model/firmware/serial first, and shows up to 120 rows.
- Report: removed the sentence telling the client that OPC UA payloads are not decoded — they are now. The remaining caveat names what still isn't (SINAUT ST7, S7comm Plus, OPC UA under SignAndEncrypt beyond the handshake, serial).
- Demo: the historian's OPC UA session now includes the OpenSecureChannel (policy None, certificate CN) and an anonymous ActivateSession, so the client table and the draft finding show the full case.

## v0.6.0 — 2026-09-05
- OPC UA decoder. Recognised by its message signature on any TCP port, not just 4840. From Hello, OpenSecureChannel, CreateSession, GetEndpoints, FindServers and ActivateSession it records: endpoint URL (which also names the server), application name/URI and product URI for both client and server, the security policies and modes the server offers, the user-token types it accepts, how the client actually authenticated (anonymous / user name — the user name is kept, the password never is), the sender's certificate CN, and a software vendor (Kepware, AVEVA, Ignition, Prosys, …) or, for controller-embedded servers (Siemens, Rockwell, Beckhoff, B&R, WAGO, Phoenix, Schneider, Omron), the manufacturer. Bodies are only readable on channels using SecurityPolicy None or Sign; under SignAndEncrypt you still get Hello and OpenSecureChannel. Every field is validated as it is read, so an encrypted body yields nothing rather than garbage.
- New auto-drafted observation: "OPC UA endpoints allow unencrypted or anonymous sessions", raised when a server advertises SecurityPolicy None / MessageSecurityMode None / an anonymous token, or a client is seen using them. Mapped to SR 1.1, 1.2, 3.1, 4.3 and T0842/T0859/T0855/T0830.
- EtherNet/IP explicit messaging. Identity-object reads (Get_Attributes_All and Get_Attribute_Single, directly or wrapped in an Unconnected_Send) are paired with their responses via the encapsulation sender context, so a device answers with vendor, device type, product code, firmware revision, serial and product name — the same fields ListIdentity gives, but now also collected when an HMI or RSLinx browses a device that never broadcasts. The requester is tagged as an EtherNet/IP client. ListIdentity and explicit reads share one table of CIP vendor ids (Rockwell, Omron, Schneider, Siemens, Phoenix, …) and device types (PLC, HMI, drive, I/O, comms adapter, managed switch), which now feed the manufacturer field and the Purdue level suggestion. Firmware is rendered Rockwell-style (20.011).
- Claims a message makes about the *receiver* (a Hello names the server it is sent to) are now attributed to the receiving asset, not the sender.
- Demo data gains an OPC UA session (AVEVA historian collector → KEPServerEX on SCADA-A, plaintext with anonymous allowed) and an RSLinx-style identity read of the HSP PLC. The demo database now rebuilds itself whenever a newer demo.py ships, instead of only when it is missing.

## v0.5.0 — 2026-09-04
- Findings now carry framework references: IEC 62443 requirements (62443-3-3 SRs, plus 62443-2-4 practices for patching and backup/restore) and MITRE ATT&CK for ICS techniques. Every auto-drafted observation arrives with its references pre-filled from a conservative mapping (evidence gaps cite the requirement they leave unverified and no ATT&CK technique — a missing SPAN port is not an adversary behaviour); assessors edit them like any other field, with a pick-list of IDs that expands "SR 5.1" to "SR 5.1 Network segmentation" on save. Shown under each finding in the register and as a "Framework references" line per finding in the Word report. Demo findings updated. Existing databases gain the two columns automatically.
- Fixed: "Import auto-drafted observations" imported nothing once the register had a single entry — the draft list was being replaced by the register itself. Same bug affected the demo builder.

## v0.4.30 — 2026-09-04
- Purdue diagram redrawn so it can be read without a decoder ring. Each zone pair now has its own vertical lane (no two lines share an x), the two end dots sit inside the bands they join instead of on the boundary between bands, and the stretch through any band in between is thin and faded so "passing through" no longer looks like "stopping here". Every line carries a numbered badge that matches the row number in the zone-pair table and a numbered legend under the diagram, so the exported SVG explains itself.
- Click a zone-pair row (or a line) to highlight that conduit and fade the others; hover previews it; click again to clear. Clicking a line scrolls the table to its row.

## v0.4.29 — 2026-09-04
- The Communications table's auto-fit was shrinking every column by the same percentage regardless of how tight it already was. That left the Conduit decision column — a select, a purpose field and a Save button all packed into one cell — squeezed below what its own controls need, while Endpoint A/Endpoint B sat mostly empty next to it. Columns now give up width in proportion to their own slack: a column already near its floor keeps its space, a column with room to spare gives more of it up. The Conduit decision column also gets a wider floor of its own (280px) to match what it actually holds.

## v0.4.28 — 2026-09-04
- Losing the server no longer shows browser internals ("Unexpected end of JSON input", "Failed to fetch") every few seconds. The page now says plainly that it can't reach the OT Scout server, keeps a red banner under the header while the outage lasts, retries quietly and confirms when it reconnects. Applies to the background poll, the loaders and the PCAP/CSV uploads.
- "About" link in the top-right corner: running version plus the full change log, read from the CHANGELOG.md shipped in the build.
- "Assessment guide" link next to it: a generic step-by-step plan for an assessor — before arrival, then Collect → Sites → Inventory → Communications → Zones → Findings → Report, plus a short "things that go wrong" list. Lives in ASSESSMENT_GUIDE.md so it can be edited without touching the app.
- Two older bugs caught while checking the above: the DEMO DATA pill in the header was showing all the time, not just on the demo data set (a styling rule was overriding the "hidden" flag), and the "No sites yet" line from the Sites tab was leaking onto the bottom of every tab (a stray closing tag ended the Sites pane early). Both fixed.

## v0.4.27 — 2026-09-04
- The last column's resize handle from v0.4.26 was being created but immediately hidden by a leftover CSS rule from the old design (where the last column, usually Edit, wasn't resizable on purpose). Removed that rule — the Edit column's handle is now actually visible and draggable, not just present in the page's code.

## v0.4.26 — 2026-09-04
- Table columns now auto-fit to the visible panel the first time each table is actually shown, so nothing (including the Edit column) starts off hidden behind a horizontal scrollbar you have to discover. Every column is resizable now, including the last one, which previously had no drag handle at all.
- "Passive by default" is now a slim one-line note under the tabs instead of a bordered yellow banner at the top of every tab.

## v0.4.25 — 2026-09-04
- The v0.4.24 fix wasn't enough — 64px was sized against this environment's font rendering, not real-world Chrome on Windows/Mint, where a bold "Edit" needs more room. Raised the column-width floor to 96px and, as a hard backstop regardless of column width, made button labels `white-space:nowrap` everywhere — a squeezed button now clips or overflows its cell instead of ever wrapping into a vertical stack of single letters again.

## v0.4.24 — 2026-09-04
- Fixed the resizable-column minimum: narrow columns (like the trailing Edit-button column) could be dragged, or on some window sizes even land automatically, below the width "Edit" needs to render on one line — the button then wrapped to one letter per line. Raised the floor to a width that comfortably fits a short button label, and any width already saved from before this fix now self-corrects to the new floor on next load instead of requiring it to be cleared by hand.

## v0.4.23 — 2026-09-03
- Capture throttle: a "Throttle" control on the Collect tab caps how many packets/sec the tool reads and processes (Unlimited / 50 / 200 / 1,000 pkt/s), for a constrained collection laptop or a fragile SPAN setup. Applies to both live capture and PCAP import. Capture stays strictly read-only either way — nothing is ever sent to the wire — this only paces how fast the tool itself works through already-mirrored traffic. The active setting shows next to the capture status while running.
- Header logo swapped for a bolder, higher-contrast mark — the previous transparent version still read as a dim smudge at the small size the header renders it at.

## v0.4.22 — 2026-09-03
- Header logo swapped for a transparent-background version — the previous one carried its own dark square backing, which disappeared against the header's dark navy. Favicon (browser tab) keeps the solid-background version, since that needs to read on any background.

## v0.4.21 — 2026-09-03
- Added the OT Scout icon to the app header (next to the title) and as the browser tab favicon.

## v0.4.20 — 2026-09-03
- Table columns are now drag-to-resize, spreadsheet-style, across every data table (sessions, checklist, inventory, communications, discovery, flows, zone pairs, findings). Drag the handle on a column's right edge; widths are remembered per browser between visits.

## v0.4.19 — 2026-09-03
- Fixed the version shown in the browser (page title and header) not matching the actual running version. It was hardcoded as literal text in `index.html` and in the HTTP server banner, separate from the real `__version__` — bumping the version in one place silently left the page showing the old number. The page now reads the version from the server at request time, so this can't drift apart again.

## v0.4.18 — 2026-09-03
- Fixed the Purdue zone diagram cutting long asset names at a fixed character count (could land mid-word, e.g. "Chlorine residual analyser" showing as "...anal"). Names now truncate on a word boundary with an ellipsis.

## v0.4.17 — 2026-09-03
- Scrolling tables use most of the window height (minimum 480 px) instead of a fixed 390 px; shorter infrastructure note in the asset table.

## v0.4.16 — 2026-09-03
- Page reorganised into tabs in engagement order: Collect, Sites, Inventory, Communications, Zones, Findings, Report. Summary strip (assets, identities, relationships, findings, sessions, visibility pill) stays visible on every tab; last tab remembered across reloads; raw flows collapsed by default; exports gathered on the Report tab; "Clear prototype data" moved to Report, away from the capture controls.

## v0.4.15 — 2026-09-02
- Network legs shown as cards with a labelled field grid and a coverage line (visibility pill, sessions, duration, packets, assets seen) instead of a nine-column input table; works at narrow widths.

## v0.4.14 — 2026-09-02
- Visibility-confidence panel restructured: heading, coloured status pill (mirror / mixed / access-port / PCAP / none), verdict as a paragraph, caveat below.

## v0.4.13 — 2026-09-02
- "Load demo data" button in the header switches the running app to the fictitious demonstration database (built on first use), with a DEMO DATA marker and "Back to my data" to return; the live database is never touched. Switching is blocked while a capture is running.

## v0.4.12 — 2026-09-02
- Coverage is judged across all collection points (mirror/TAP at some, access-port at others) rather than the most recent session only; report and executive readout describe the mixed case per collection point.
- `demo.py` builds `data/demo.db` for a fictitious water utility and writes `demo-report.docx` / `demo-purdue.svg`; run the app on it with `sudo python3 run.py --database data/demo.db`.
- Documented-assets panel laid out like the other panels; CHANGELOG.md added and shipped with every build.

## v0.4.11 — 2026-09-02
- Idle CPU fix: computed views are cached until a write; the page polls a lightweight status call and refetches tables only when the server change counter moves; tables are not re-rendered unless their data changed; Purdue-level suggestion uses two grouped queries instead of 18 per asset; status polling no longer logged.

## v0.4.9 – v0.4.10 — 2026-09-02
- Documented assets: add devices singly or in bulk from the downloadable CSV template, with source of record, asset tag, manufacturer/model/serial/firmware and lifecycle fields (install date, end of life, end of support, support status, patch status, backup status, last backup). A row with a MAC links to passive evidence; re-import updates; rejected rows reported by row number.
- Merge identities: fold a second NIC into one physical asset; the merged MAC becomes an alias.
- Report: evidence-source breakdown, lifecycle observations table, draft findings for end-of-life assets and missing/unverified backups.
- Import controls labelled (0.4.10).

## v0.4.8 — 2026-09-02
- Network infrastructure (gateways, switches, access points) is its own class in zone analysis: own band in the diagram, not a boundary crossing, excluded from the assigned-level count; an explicit assessor level still overrides.

## v0.4.7 — 2026-09-02
- Suggested Purdue level per physical asset from protocol role, payload role fingerprints and device type, with confidence and evidence; apply per asset or "Accept suggested levels"; report records assessor-set versus suggestion-accepted levels.
- External endpoints that resolve to many IPs merge into one relationship on the DNS name.
- Conduit decisions save on change; tables no longer rebuilt underneath an edit by the refresh cycle.

## v0.4.6 — 2026-09-02
- Purdue zone and conduit analysis: inline level assignment; relationships carry zone pair and boundary crossed; conduit decisions (Approved / Tolerated / Unexpected / Unknown) with purpose per endpoint pair.
- Zone-pair matrix and Purdue band diagram, exportable as SVG.
- Report section 4 gains zone assignment, boundary-crossing and conduit-status tables; draft findings for unexpected conduits, DMZ bypasses, unreviewed crossings and unassigned assets.
- Secondary-interface detection requires a network-equipment OUI so sequential controller MACs are never merged.

## v0.4.5 — 2026-09-02
- Findings and observations register (type, rating, confidence, owner, condition, evidence, impact, recommendation, closure, horizon, status; FND/OBS/POS references); auto-drafted observations importable once, then editable.
- Report renders the register when populated, shows validation status, excludes rejected items, rolls the roadmap up from horizons.

## v0.4.4 — 2026-09-02
- Placeholder and self-referential hostnames (localhost, MAC/IP-derived .local names) no longer become asset names; existing ones purged on startup.
- Adjacent same-manufacturer MAC with no IP evidence classified as a likely secondary interface.
- Draft observation when assets from more than one IPv4 subnet share a Layer-2 segment.

## v0.4.3 — 2026-09-02
- Site validation: per-site checklist (facility function, ingress/egress, asset categories and switching, SCADA/historian, remote access, telemetry, documentation and deviations, interviews, configuration/log review, walkdown, safety) with status, evidence reference and notes.
- Collection-point matrix: network legs per site with Purdue level, evidence source, status, time window, exclusions, limitations; coverage per leg computed from matching capture sessions.
- Report fills the evidence-sources table from the checklist and adds site-validation and coverage-by-leg sections.

## v0.4.2 — 2026-09-02
- Passive decoders for DNP3 (link addresses, master/outstation direction, function, IIN flags; header CRC validated), Siemens S7comm (COTP TSAP rack/slot, SZL 0x0011 order number and firmware, SZL 0x001C identification) and Profinet DCP (station name, vendor value, vendor/device ID, role, IP); Profinet RT/alarm/PTCP frames tagged.
- Version shown in header, tab and startup line; capture timer visible when idle.

## v0.4.1 — 2026-09-02
- Live capture timer in the header (server-synced) and Duration column on sessions; `duration_seconds` in the JSON export.
- Word (.docx) assessment report generator with no third-party packages: cover, document control, executive readout, scope and evidence, coverage, inventory and fingerprints, communications and industrial-protocol observations, auto-drafted observations, roadmap, appendices. Also runnable offline: `python3 -m ot_scout.report assessment.json report.docx`.

## v0.4 — 2026-09-02
- Separates unicast relationships from broadcast/multicast/service-discovery traffic; relationship categories; capture-interface provenance.
- Improved gateway/transit detection; routed public addresses suppressed from a gateway's identity.
- Manufacturer-based device classifications; derived virtual MAC identities stay virtual.
- Broadcast/service-discovery table and CSV export.

## v0.3.1
- Derived, locally administered identities corrected so LLDP volume does not create phantom assets; asset table layout stabilised.

## v0.3
- Passive fingerprints: DHCP, HTTP, LLDP, Modbus device identification, EtherNet/IP ListIdentity, BACnet I-Am.
- Automatic device-type classification with evidence and confidence; assessor overrides retained alongside.
- Likely physical assets separated from all observed L2 identities; deduplicated relationships separated from raw flows.
- Assessment context fields (location, criticality, Purdue level, ISA-62443 zone, function, safety impact, owner, notes); expanded CSV/JSON exports.
