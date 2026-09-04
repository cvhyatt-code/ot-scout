# OT Scout assessment guide

A high-level plan for running a passive OT/ICS assessment with this tool. It follows the tabs left to right — that order is the order the work actually happens in. Everything OT Scout produces is evidence, not proof of coverage: the walkdown, drawings and interviews are what make it an assessment.

## 0. Before you arrive

- Agree scope in writing: sites, network legs, what is explicitly out (safety systems, vendor-managed cells, remote sites).
- Confirm you have a **mirror/SPAN port or a TAP** at each collection point. An ordinary access port only shows you broadcast traffic plus whatever talks to your laptop — the visibility pill will tell you which one you got.
- Get the change/approval for plugging in. Capture is read-only (the tool never sends a packet), but plant operations still needs to know.
- Ask ahead for: network drawings, switch configs or port maps, the site's own asset list, historian/SCADA tag lists, remote-access inventory.
- Bring the collection laptop with OT Scout installed and tested (`python3 -m unittest discover -s tests`, then run it once). Decide your **Throttle** setting: leave Unlimited unless the site asks you to be gentle on an old SPAN setup or your laptop is struggling.

## 1. Collect

- Fill in Assessment, Site, Collection point and Access method **before** starting — they label every session and drive the coverage verdict in the report. Be honest with Access method; "Unconfirmed access port" is the right answer until someone shows you the mirror config.
- Start the capture. Aim for a window that covers a full operational cycle (shift change, a batch, a backwash, a polling interval) — 20 minutes of quiet plant tells you less than 2 hours.
- Watch the **Visibility confidence** panel. If it says access-port only, stop and fix the mirror before burning time.
- Move to the next collection point and repeat with a new Collection point name. One session per leg is the goal.
- Have a PCAP from someone else (vendor, IT, a previous visit)? Import it here — it becomes its own session with visibility marked unknown.

## 2. Sites

- Create the site and work the **site-validation checklist**: facility function, ingress/egress, asset categories, SCADA/historian, remote access, documentation, interviews, walkdown, safety. Record status and an evidence reference (photo IDs, document names, who you interviewed).
- Add one **network leg** per physical or logical segment and link each to the collection point you captured at. Coverage per leg is computed from that link — a leg with no session is an evidence gap, and the report says so.
- Write down exclusions and limitations while you still remember why.

## 3. Inventory

- Review the passive inventory. Fix device types the fingerprinting got wrong, merge second NICs into one physical asset, and fill in location, criticality, owner and function for anything that matters.
- Add **documented assets** the capture cannot see: serial PLCs, RTUs, radios, safety controllers, spares. Use the CSV template for bulk entry from the site's own list. A row with a MAC links to passive evidence when that MAC shows up; a row without one stays "documented, not observed" — that is a legitimate, reportable state.
- Capture lifecycle data (install date, end of life/support, backup status). These feed draft findings automatically.

## 4. Communications

- Read the deduplicated relationships, not the raw flows. Ask of each one: is this expected? Who owns it?
- Record a **conduit decision** — Approved, Tolerated or Unexpected — with a one-line purpose. Unknown is fine during collection; it should not survive to the report.
- Broadcast/service-discovery traffic is a separate table on purpose. It is useful for spotting rogue services and IT protocols leaking into OT, but it is not a relationship.

## 5. Zones

- Assign a **Purdue level** to every physical asset. Accept the suggested levels where the evidence is good, then correct against drawings and what you saw on the walkdown.
- Look at the zone-pair matrix. Boundary crossings, DMZ bypasses and direct external conversations are where findings come from.
- Export the diagram — it goes in the report and it is the picture the client remembers.

## 6. Findings

- Import the **auto-drafted observations**. Every one is a draft: validate it, rewrite it in plain language, set rating and confidence honestly, name an owner and a horizon. Reject the ones that are not real.
- Add your own findings from the checklist, interviews and walkdown. Positive observations belong here too.
- Each finding carries IEC 62443 and ATT&CK for ICS references — pre-filled on the drafts, editable on everything. They are what an auditor or insurer will ask for; keep them honest (an evidence gap gets the requirement it leaves unverified, not an attack technique).
- Confidence should reflect the evidence: a single access-port session does not support a "Confirmed" finding about what a segment talks to.

## 7. Report

- Fill in Prepared for / Prepared by and generate the Word report. Read the coverage section first — if it says access-port visibility, so will the client, and the rest of the report has to be written with that caveat.
- Export the assessment JSON alongside it. It is the evidence package: keep it with the engagement record so the report can be re-rendered or challenged later.
- Clear prototype data only after the exports are safely stored.

## Things that go wrong

- Tool shows "Can't reach the OT Scout server": the app on the collection laptop has stopped or the network between you and it has changed. Check the terminal it is running in.
- Lots of identities, few physical assets: locally-administered or virtual MACs. Normal on segments with VMs, HA pairs or LLDP-heavy switches; the inventory separates them.
- Many assets, no relationships: you are on an access port. Fix the mirror.
- Nothing at all: wrong interface selected, or the capture was started without root.
