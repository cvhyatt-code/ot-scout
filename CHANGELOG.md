# OT Scout changelog

All notable changes to OT Scout. Versions are shown in the page header, browser tab and the startup line printed by `run.py`.

## v0.18.0 — 2026-09-13
- **The Engagement panel is now an engagement manager.** Opening an engagement shows what it actually owns: the database and its size, every session with its collection point, frame count and the raw capture it wrote, and whether an evidence package was ever exported from it. You should never be asked to destroy something you have only been told the size of.
- **Deleting a finished engagement is a first-class action**, in a Danger zone at the bottom of that view, shaped after the way GitHub deletes a repository: it enumerates exactly what goes, and the button stays disabled until you type the engagement's own name. Nothing is moved to a recycle bin — the database and the captures it owns are unlinked.
- **You cannot delete the engagement you are standing in.** Switch away first. GitHub lets you delete the repository you are looking at; here that costs one click to avoid and removes a whole category of mistake, so the thing being destroyed is never the thing on screen.
- Deletion resolves each capture from the session that wrote it, and then refuses to unlink anything that does not resolve inside `data/captures/` — the path comes out of a database, and a database is not a trusted source. Files belonging to other engagements are never touched; there is a test for exactly that.
- The delete dialog reports whether an evidence package was exported and when, recorded when you generate one. It is deliberately a statement of fact and not a gate: OT Scout cannot know whether that export is stored anywhere safe, and a check it cannot really make is worse than no check, because it invites you to trust it.
- **Reset is gone.** It emptied the current database's tables while leaving every raw capture on disk, so an assessor who pressed it believing the laptop was clean had deleted the index and kept the recording. Starting over is now a new engagement, which destroys nothing; finishing up is deleting the old one, which destroys all of it deliberately. It also sat on the Report tab two panels below "Export evidence package", which is the worst possible neighbour for a delete-everything button.
- The header chip carries a chevron. It names the current engagement, which was the point, but nothing about it suggested that clicking it opened all of them — the affordance was in a tooltip, and tooltips are invisible.
- `GET /api/engagements/detail`, `POST /api/engagements/delete`. `tests/test_engagements.py` grows to 38 tests; the suite is now 164.

## v0.17.1 — 2026-09-13
- Header rebuilt in three zones — identity, which data set is on screen, what the tool is doing — separated by dividers rather than by spacing. It had accumulated five different kinds of thing at one visual weight, so nothing indicated what to read first.
- **"Prototype" is gone.** It was accurate while the repository was private; now it invites a reader to dismiss the tool before looking at it. The header reads *OT Scout · Passive OT/ICS assessment*, with the version as a small chip beside the name — `CONTRIBUTING.md` asks people to quote it when reporting a bug, so it stays visible. The word is also gone from the startup line, the About dialog, the argument parser, the module docstring, the PCAP error and the User-Agent sent to the IEEE registry, which had been pinned at a hardcoded `0.2` for some time and now reports the real version.
- Loading the demonstration data moved out of the header and into the Engagement panel. It is a data-set switch, the same operation as changing engagement — two buttons side by side doing the same kind of thing, with no relationship between them, was most of why the header read as accreted. The separate DEMO DATA pill goes with it: the engagement chip turns amber and reads *Data set* instead.
- Capture status and the elapsed timer became one element with a status dot — green while capturing, red on error. The timer is hidden entirely when nothing has run, rather than showing a permanent `0:00`.
- The Engagement panel closes once you have chosen, instead of leaving you to dismiss it.
- The standing "Passive by default" banner is gone from every screen. The caveat still reaches the people who need it: `README.md` states it, and the Word report tells the client that missing observations are treated as unknown rather than as proof of absence. On the assessor's own screen it was read once and ignored thereafter.
- **Clear prototype data** is now **Clear this engagement's data**, and its confirmation names what it deletes. With engagements, "prototype data" was actively misleading — the button removes real work.

## v0.17.0 — 2026-09-13
- **Engagements.** One customer, one database — the practice `INSTALL.md` already recommended, now something the tool does rather than something you have to remember. **Engagement** in the header opens a panel that starts a new engagement (names it, creates its own database, switches to it) and lists the existing ones to return to. Nothing is deleted by either action; the engagement you leave is exactly as you left it.
- The engagement you are in is named in the header at all times, next to the demo pill. That is not decoration. Switching used to require restarting with `--database`, which was hard to do by accident; a button is two clicks, so the current engagement has to be visible without being asked for.
- Both actions confirm first, and say what actually happens: the other engagement is untouched, everything on screen is replaced, and a running capture is not stopped — the switch is refused instead, as it always has been.
- Each database records its own engagement name (new `meta` table). Databases made before this release describe themselves using the assessment name of their first session, so existing work appears in the list with a sensible name and nothing needs migrating.
- The switch target is a filename supplied by the browser, so it is reduced to a basename and required to resolve inside the data directory. Listing reads every candidate database strictly read-only — going through `Store` would have created the schema, quietly adopting any unrelated SQLite file in `data/` as an engagement.
- `GET /api/engagements`, `POST /api/engagements/new`; `POST /api/database/switch` now also accepts an engagement's filename. `/api/status` and `/api/database` carry the engagement name.
- New `tests/test_engagements.py` (21 tests), including the traversal cases. Suite is now 147.

## v0.16.1 — 2026-09-13
- The fields that name a customer no longer follow you to the next engagement. Assessment, Site, Collection point and the report's "Prepared for" were remembered in browser storage under one global key, so they survived a database reset, a switch to a different `--database`, and a switch to the demo set and back. Finish at one site, start at another, press Start without re-reading the form, and that site's name is on the session, in the Word report and in the evidence package. They are now keyed to the database in use — one per engagement, as `INSTALL.md` recommends — and cleared when you reset. What stays remembered is what belongs to the laptop rather than the customer: the capture interface, the throttle, the save-PCAP setting, the assessor's own name and the report title and banner.
- Reset says what it clears, since it now clears more than the database.

## v0.16.0 — 2026-09-13
- A frame the decoder cannot handle now costs that frame and nothing else. Every byte OT Scout parses was chosen by whoever is on the monitored network, or by whoever wrote the PCAP someone handed you, and an exception escaping the decode call killed the parser thread — which then wedged the reader thread on the stop sentinel, leaving the capture permanently "running" until the process was killed. The decode call is wrapped, the frame is counted as `malformed` and stays in the raw PCAP, and the capture carries on.
- CIP `Unconnected_Send` unwrapping is bounded at 8 hops (`MAX_ROUTE_DEPTH`). Real routing nests a few; a crafted request could nest thousands, and the recursion that follows the embedded request ran until the interpreter stack gave out. A 20 KB frame was enough — trivially so from an imported PCAP, which `SECURITY.md` already treats as attacker-controlled.
- Stopping a capture no longer depends on the parser thread still being alive. The stop sentinel went through the same bounded queue as the frames, so a busy capture — the exact case where the queue is full — blocked the reader until the parser made room. If the parser was gone, that wait never ended.
- The web interface refuses requests carrying an unrecognised `Host` header (421) and state-changing requests carrying a foreign `Origin` (403). Binding loopback keeps other machines out; it does nothing about a page on the internet pointing a hostname it owns at 127.0.0.1 so the assessor's own browser fetches the evidence export and reads it back as same-origin, or simply POSTing to `/api/reset`. With no authentication to check, these two headers are the whole boundary. Requests with no `Origin` at all — curl, scripts, `copilot.py` — are unaffected, and `--insecure-bind` still answers to any name.
- Capture status reports a `malformed` count alongside `dropped` and `unparsed`.
- New `tests/test_hostile_input.py` (17 tests). Suite is now 119.
- "OT Scout transmits nothing" was too broad, and it is the claim the tool is sold on, so it is now scoped where it is true: nothing is ever sent **on the capture interface**. Two features do reach the internet, neither on its own and neither on that interface — the IEEE OUI download behind "Update vendor database", and Scout Assist on a cloud backend. `INSTALL.md` names both in a table, `ASSESSMENT_GUIDE.md` says to settle them before you travel, and `README.md` and the About dialog no longer overstate it.
- New `NOTICE`: MITRE's required attribution for the ATT&CK for ICS technique identifiers and names in `frameworks.py`, a statement that the 62443 short descriptions are this project's paraphrases rather than the standard's clause titles, and the IEEE MA-L registry as the source of the vendor table. Neither MITRE nor the IEC endorses this tool, and `NOTICE` says so.
- `INSTALL.md` no longer warns that Start capture crashes on Windows — it has refused cleanly with an explanation since v0.15.0.
- The v0.11.0 entry described the drop-storm capture as coming from "the mirror" on a named laptop; it was a development machine on an ordinary network, and it now says so. The v0.13.0 entry no longer describes its report ideas as taken from a named commercial product — they are conventions the OT monitoring platforms established generally.
- The Collect form no longer ships pre-filled with "Home Network Prototype", "Home" and "Linux Mint Ethernet" — leftovers from development that every user inherited as defaults. They are placeholders now. These three fields label every session, follow the evidence into the report and the evidence package, and drive the coverage verdict; a pre-filled value an assessor does not notice is a client report labelled with someone else's site.
- The demo data set's two external endpoints move to `203.0.113.0/24` (RFC 5737, reserved for documentation). The previous pair were invented, but both landed in real allocated commercial space, and the demo presents them as an unknown camera's cloud endpoint and an integrator's RDP ingress. Nothing should point a security example at somebody's actual address.
- `private_or_local_ip` now treats the RFC 5737 and RFC 3849 documentation ranges as outside the site. Python's `is_private` counts them as private because they are not globally routable, which is the wrong question here: those addresses should never appear on a plant network, so a controller talking to one is an anomaly the assessor should see rather than a row filed as "Unmapped local". Without this the demo's two external conversations were classified as local and its boundary findings lost their evidence.
- Documentation screenshots re-taken at v0.16.0. The old set was v0.14.0 and showed the pre-paraphrase IEC 62443 clause titles, the two commercial IP addresses and the pre-filled Collect form.
- `docs/OT_Scout_Walkthrough_v0.14.pdf` removed. It carried eleven of the old screenshots baked in as images — the pre-paraphrase clause titles, the two commercial addresses and the pre-filled Collect form — it could not be regenerated from a clone because the source deck lives outside the repository, and it was 2 MB of a 4.3 MB `docs/` directory that would go stale at every release. `docs/img/` covers the same ground and is current; `README.md` points there instead.
- Four tests for address scope. Suite is now 123.

## v0.15.1 — 2026-09-13
- The About dialog now carries the licence notice: copyright, that the tool comes with absolutely no warranty, that it is free software under the GNU Affero General Public License v3 or later and may be redistributed under those terms, and a link to the source. AGPL section 0 asks an interactive interface to display those, and section 13 wants anyone who reaches a modified version over a network to be able to get the source; the About dialog is the place for both.

## v0.15.0 — 2026-09-13
- The web interface refuses to bind a non-loopback address. It has no authentication — every endpoint is open to whoever can reach the port, including evidence export, database reset and the Scout Assist model settings that hold an API key — so `--host 0.0.0.0` now exits with a message naming exactly what would be exposed and pointing at `ssh -L` or `tailscale serve` instead. `--insecure-bind` still permits it for anyone who means it, with a startup banner. Previously a one-word flag put an unauthenticated control plane for a live assessment onto the network being assessed, and nothing said so.
- Live capture now fails cleanly off Linux. `start()` checks for `AF_PACKET` before spawning the capture thread and returns "Live capture requires Linux — import a PCAP instead", rather than an `AttributeError` raised inside a thread where nobody sees it. Everything downstream of capture — import, inventory, zones, conduits, findings, the report — already ran on any platform; now the tool says so instead of appearing broken.
- pcapng files are recognised and explained. Wireshark and dumpcap write pcapng by default and OT Scout reads classic libpcap, so the old "Only classic Ethernet PCAP files are supported" left people stuck on the most likely file they would be handed. The error now names the fix: `editcap -F libpcap in.pcapng out.pcap`, or `dumpcap -P` to capture in pcap format to begin with.
- New `INSTALL.md`: which platforms do what, hardware, the SPAN/TAP conversation to have with the plant, why root buys both the raw socket and the 64 MB receive buffer, how to read dropped (gone) versus unparsed (recoverable from the PCAP) frames, remote access, getting the evidence off and verifying it, where the data and the API key live, and cleaning up afterwards.
- New `ot_scout/bind.py` and `tests/test_bind_guard.py` (11 tests).

## v0.14.0 — 2026-09-05
- Conduit drawer: every relationship in the selected zone pair carries its Approved / Tolerated / Unexpected / Unknown decision and business-purpose note, saved on change; the zone-pair table, diagram and drawer refresh together. Unreviewed relationships sort first with a count in the heading; a colored edge shows each decision; long lists are capped at 25 with "Show all". Conduit review no longer requires the Communications tab.

## v0.13.0 — 2026-09-05
- Purdue tab: selecting a conduit (table row or diagram line) opens a drawer with the findings that cite it (rejected/superseded drafts folded away), the relationships in that zone pair with their decisions, and a "Draft finding from this conduit" button that opens the finding dialog pre-filled and pre-linked. An Unexpected conduit with no live finding is flagged in the drawer.
- `GET /api/findings/for?kind=pair|relationship|asset&key=…` — findings citing an evidence item.
- Finding dialog round-trips `links`, so saving from the drawer records the conduit the finding came from.

## v0.12.1 — 2026-09-05
- `save_finding` accepts a links-only update (`{"id": …, "links": […]}`), which is what linking a finding to a conduit from the UI will send.
- Demo shows the intended workflow on the new links: the assessor-written camera (FND-01), vendor RDP (FND-02) and cleartext-management findings are linked to their relationships, zone pairs and assets; the auto-drafts they supersede ("OT assets communicate directly with external…", "External communication pathways require policy validation") are Rejected instead of sitting in the register as duplicates.

## v0.12.0 — 2026-09-05
- Findings now link to the evidence they cite: `finding_links` table (kinds `relationship`, `asset`, `pair`); every auto-draft carries its links; `Store.findings_for(kind, key)` answers "which findings cite this conduit / asset / zone pair" (a zone-pair query also matches findings linked to relationships inside it). `save_finding` accepts `links`; `link_finding` / `unlink_finding` for manual edits. Register rows carry `links` in `/api/findings`.
- Draft import matches on a stable `draft_key` instead of the title, so retitling a finding no longer causes a re-import to duplicate it; existing registers are back-filled by title once.
- Conduit drafts split by crossing class: OT-to-external/internet, DMZ bypass, other unexpected. The DMZ-bypass draft is no longer suppressed when something is marked Unexpected (previously an internet-facing camera and two DMZ bypasses landed in one finding whose title mentioned neither). Bypass draft confidence rises to High when any of its relationships is marked Unexpected.
- New draft "OT assets communicate directly with external or internet endpoints" (SR 5.1/5.2/5.4; T0883/T0822/T0886).

## v0.11.1 — 2026-09-05
- PCAP import is refused while a live capture is running (the Import button is disabled with the reason). The drop storm in v0.11.0's notes turned out to have happened during an import: parsing a file in the request thread competes with the live reader for the CPU and the SQLite lock, and the old 200 KB socket buffer had no chance. Same guard the app already applies to reset, data-set switch and vendor update. 84 tests.

## v0.11.0 — 2026-09-05
- Capture pipeline rebuilt after a live session on the development laptop reported 119,261 kernel drops against 55,692 frames read (68% of the feed never reached the collector). Root cause was structural, not the disk: one thread did `recv`, the PCAP write, protocol parsing and the SQLite batch flush, against the kernel's default ~200 KB receive buffer, so the buffer overflowed whenever parsing stalled. Now: a reader thread does nothing but `recv` → PCAP → hand-off; a parser thread does parsing and SQLite; the socket asks for a 64 MB receive buffer with `SO_RCVBUFFORCE` (root, so `net.core.rmem_max` no longer caps it) and the status line shows what the kernel actually granted. The rate-limit throttle now paces the parser only — it can no longer cause drops.
- Two distinct warnings on the Collect tab. **Dropped by the kernel** (with the percentage of the mirror lost) is unrecoverable and means the session is a sample, not a census — narrow the SPAN or capture with dumpcap and import. **Saved to the PCAP but not parsed live** is new and recoverable: the parser fell more than 300,000 frames behind, the frames are on disk, import the PCAP to add them. The old "faster disk" advice is gone; it was wrong.
- Stop no longer discards the parse backlog: the status reads "Finishing — N frames left to parse" while the parser drains, then the session closes with the final counts.
- Assessment guide updated with the order of remedies (narrow the mirror, `dumpcap -B 512` + import, then hardware) and what each warning means for the report.
- 3 new tests (83 total): the parser thread drains a queue into the store and closes the session, status carries the pipeline fields, and the receive-buffer request lands.

## v0.10.2 — 2026-09-05
- Model connection moved out of the Scout Assist tab into a **Settings** dialog (header, next to Assessment guide / About). The tab is now just the question and the answer, full width; the model pill in its corner opens Settings, and a red notice with a Settings link appears when no model is connected.
- Install note: update with `unzip -o` over the existing folder — never delete `~/ot-scout-v04`, because `data/` holds the databases, PCAPs and the saved model connection.

## v0.10.1 — 2026-09-05
- The copilot is now called **Scout Assist** in the app and the docs (tab, heading, explanatory text). Internals — `copilot.py`, `/api/copilot`, `data/copilot-*.json*` — are unchanged.

## v0.10.0 — 2026-09-05
- Scout Assist tab in the app. The proof-of-concept copilot from v0.9 now has a home in the web UI as **Scout Assist** — it analyzes the evidence collected during the assessment to help identify relationships, gaps and areas requiring human validation; it does not add evidence or make final assessment decisions. In the tab: ask in plain language or click one of the eight standard questions, and the answer comes back in the same checked structure as the CLI — observed, analysis, potential concerns, alternative explanations, validate on site, insufficient evidence — with every evidence id shown as a chip and a green/red grounding pill (green means every id, IP and MAC in the reply traces to evidence OT Scout actually supplied). "Start a finding from this" opens the findings dialog pre-filled from the answer (condition, evidence, recommendation, related assets by name) so the copilot's draft goes through the same assessor review as any other finding. Earlier answers from the session are kept in a list; everything is still appended to `data/copilot-log.jsonl`.
- Model connection panel: backend (anthropic, openai, ollama, llamacpp), model, server URL, API key, max reply tokens (default 3000), evidence budget and timeout, with a Test connection button. Settings are stored in `data/copilot-settings.json` (mode 0600) on the assessment machine — never in a database, so they can never end up in an evidence package — and the key is never sent back to the browser, only "saved …1234". An `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` environment variable still works as a fallback. The panel says plainly whether the chosen backend is local (evidence stays on the box) or cloud (selected evidence is sent to the provider).
- Purdue diagram uses the space: it now scales to the panel width, the card area is sized from what the conduit lines actually need instead of a fixed 55/45 split, a band with more assets than fit in one row gets a second row before folding into "+N more", and only that band gets taller. Hovering an asset card shows its details (type, make/model, IPs, MAC, firmware, criticality, location, zone, function, protocols, support) — in the app and in the exported SVG — and clicking a card in the app opens the asset for editing.
- One question at a time: a second question while one is running is refused with the question in progress rather than queued, so a slow local model cannot pile up requests.
- CLI: `--max-tokens` default raised from 1500 to 3000 (1500 truncated Claude's answers mid-JSON during the evaluation).
- 7 new tests (80 total): settings persistence and key masking, validation, ask/log/history through the service, the grounding check flagging invented evidence, the one-at-a-time lock, and the three `/api/copilot*` routes through the real HTTP handler.

## v0.9.1 — 2026-09-05
- Fixed a timeout that cut off local-model runs before they finished. Cold-loading a 7B GGUF model plus CPU-only prompt processing can take well past the old 600s ceiling; `Backend`'s default `timeout` is now 1800s and it is exposed on the CLI as `--timeout` so a slower box (or a bigger model) can be given more room without editing code.

## v0.9.0 — 2026-09-05
- Assessment copilot (proof of concept): `python3 copilot.py --database data/demo.db` puts a language model on top of the assessment export so the assessor can ask "which relationships should I investigate first?", "why is WTP-EWS01 interesting?", "draft a finding for this unexpected path" or "summarise this for an executive". The model reasons over OT Scout's evidence; it never creates evidence — it is not consulted about whether an asset exists, what a protocol is, or what level anything sits at. Nothing in capture, parsing, the store or the UI changed.
- Evidence identifiers: every record sent to the model carries a stable id — ASSET-007, REL-012, FLOW-042, CAP-001, SITE-002, and the register's own FND-/OBS-/POS- refs — and the model is required to cite them. Only the evidence relevant to the question is sent (unexpected/unreviewed/external relationships and both their endpoints first, then undocumented, low-confidence and high-exposure assets, findings and captures for executive questions, an asset plus its relationships and flows when the question names one), within a character budget (`--budget`, default 12,000 ≈ 3,000 tokens) because a 7B model on a CPU reads its prompt at a few dozen tokens a second.
- Structured, checked answers: the model must reply as JSON with observed facts, analysis, potential concerns, alternative explanations, recommended validation, evidence ids, confidence and what evidence is missing. Every answer is then checked — evidence ids it cites but was never given, and IP or MAC addresses in its text that appear nowhere in the supplied evidence, are flagged as unsupported. That flag is the hallucination meter for the evaluation.
- Backends behind one prompt: `--backend ollama` (default, local, model `qwen2.5:7b`), `llamacpp` (a local `llama-server`), `openai` (OpenAI or any OpenAI-compatible `--url`) and `anthropic`. Same prompt and same checks whichever answers, so a frontier model can be used to tune the prompt on the fictitious demo data and a local 7B model tested against the same questions before any customer evidence is involved. Standard library only; no SDKs.
- Evaluation log: every exchange is appended to `data/copilot-log.jsonl` with backend, model, question, evidence ids sent, prompt size, latency, time to first token, token counts where the backend reports them, the raw reply and the grounding check. `--eval` runs the eight standard questions; `--log-summary data/copilot-log.jsonl` tabulates answers / valid JSON / grounded / median latency per model. `--dry-run` prints the exact prompt without calling anything.
- 19 new tests (73 total) cover identifiers, selection order and budget, JSON recovery from fenced or prose-wrapped replies, the grounding check catching an invented relationship and address, logging, the backend factory, and the Ollama / OpenAI-compatible / Anthropic stream parsers against a fake local server.

## v0.8.0 — 2026-09-05
- Exposure score per asset (0–100, banded Low/Moderate/High/Critical). A prioritisation aid built only from what the assessment already holds — assessor-recorded criticality, boundary crossings and their conduit decisions, external and DMZ-bypass paths, lifecycle and backup state, cleartext management services served, OPC UA security posture, and validated findings in the register that name the asset — with every point itemised ("Talks to an external endpoint, worst decision Unexpected (+25)"). Not a vulnerability or likelihood score; no CVE data. Shown as a pill on the inventory (hover for the breakdown), as an Exposure column in the report's inventory table, and as "Assets to address first" at the top of the executive readout in both the app and the Word report.
- Fleet view: the physical inventory grouped by manufacturer and model with unit count, firmware spread, end-of-life count, no/unknown-backup count and highest exposure — so "PLC-07 is end of support" becomes "both of your S7-315s are". Report tab and report section 3.
- IEC 62443 requirements addressed by the findings: a rollup of which SRs / 2-4 practices the register bears on, most-cited first, with worst rating and finding refs. Report tab and report section 5.
- New Executive readout panel at the top of the Report tab carrying the three tables above — the same order they lead the Word report in.
- The three ideas are conventions the commercial OT monitoring platforms established (a per-device risk score, "vulnerable assets by model", compliance rollups), cut down to what a point-in-time assessment can defend without a monitoring history or a peer population.

## v0.7.1 — 2026-09-05
- First real-traffic validation of the OPC UA decoder: a capture of an opcua-asyncio 2.x server and client (loopback, anonymous session then a user-name session) is now a fixture in `tests/fixtures/` with a regression test. Every expected claim came out of real bytes — server application name and product URI, endpoint, security policy/mode/tokens offered, client application, anonymous vs "User name (operator)" — and the password never appears anywhere.
- PCAP import limit raised from 100 MB to 512 MB so the public 4SICS captures (25/134/200 MB) fit. The file is read into memory during import.

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
- Findings now carry framework references: IEC 62443 requirements (62443-3-3 SRs, plus 62443-2-4 practices for patching and backup/restore) and MITRE ATT&CK for ICS techniques. Every auto-drafted observation arrives with its references pre-filled from a conservative mapping (evidence gaps cite the requirement they leave unverified and no ATT&CK technique — a missing SPAN port is not an adversary behaviour); assessors edit them like any other field, with a pick-list of IDs that expands "SR 5.1" to "SR 5.1 The network is divided into zones" on save. Shown under each finding in the register and as a "Framework references" line per finding in the Word report. Demo findings updated. Existing databases gain the two columns automatically.
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
