# OT Scout assessment guide

A high-level plan for running a passive OT/ICS assessment with this tool. It follows the tabs left to right — that order is the order the work actually happens in. Everything OT Scout produces is evidence, not proof of coverage: the walkdown, drawings and interviews are what make it an assessment.

## 0. Before you arrive

- Agree scope in writing: sites, network legs, what is explicitly out (safety systems, vendor-managed cells, remote sites).
- Confirm you have a **mirror/SPAN port or a TAP** at each collection point. An ordinary access port only shows you broadcast traffic plus whatever talks to your laptop — the visibility pill will tell you which one you got.
- Get the change/approval for plugging in. Capture is read-only (the tool never sends a packet on the interface it captures from), but plant operations still needs to know.
- Decide before you travel whether the laptop may reach the internet at all. Two features do: **Update vendor database** (the IEEE OUI registry) and Scout Assist on a cloud backend. Run the vendor update at the office and pick a local Scout Assist model, and the machine makes no outbound connections on site.
- Ask ahead for: network drawings, switch configs or port maps, the site's own asset list, historian/SCADA tag lists, remote-access inventory.
- Bring the collection laptop with OT Scout installed and tested (`python3 -m unittest discover -s tests`, then run it once). Decide your **Throttle** setting: leave Unlimited unless the site asks you to be gentle on an old SPAN setup or your laptop is struggling.

## 1. Collect

- Fill in Assessment, Site, Collection point and Access method **before** starting — they label every session and drive the coverage verdict in the report. Be honest with Access method; "Unconfirmed access port" is the right answer until someone shows you the mirror config.
- Start the capture. Aim for a window that covers a full operational cycle (shift change, a batch, a backwash, a polling interval) — 20 minutes of quiet plant tells you less than 2 hours.
- Watch the **Visibility confidence** panel. If it says access-port only, stop and fix the mirror before burning time.
- Watch the **dropped** count under the Start button. Any number above zero means frames reached the laptop's capture socket faster than the collector read them and the kernel discarded them: the inventory and communications for that session are a sample with holes you cannot see, and "we saw no traffic from X to Y" is not a defensible statement from it. Since v0.11 the collector reads with a 64 MB socket buffer on a thread that does nothing but read and write the PCAP, so a modern laptop keeps up with a normal OT mirror; if you still see drops, the mirror is carrying too much. In order: narrow the SPAN at the switch to the OT VLANs or ports you are assessing; capture with `dumpcap -i <iface> -B 512 -w site.pcap` (Wireshark's capture engine, a ring buffer that all but eliminates drops) and import the file; only then think about hardware. The throttle never helps — it paces parsing, not reading.
- Do not import a PCAP while a capture is running (the app now refuses). Import is analysis work; capture time belongs to the reader.
- **Frames saved but not parsed live** is a different, recoverable warning: the parser fell more than 300,000 frames behind the reader. Everything is in the PCAP; import it into the same assessment to fill in what the live view missed.
- When you press Stop on a busy capture the status reads **Finishing — N frames left to parse** for a few seconds while the parser drains. Wait for Stopped before switching data sets or exporting.
- Leave **Save raw PCAP** on. The pcap is the evidence of record, and it lets you re-run a capture through a later build.
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

- Read the **Executive readout** on the Report tab first: the assets ranked by exposure are what the plant manager will ask about, and every score is itemised so you can defend it. If the ranking looks wrong, it is usually a missing criticality or an unreviewed conduit — fix the input, not the number.
- Fill in Prepared for / Prepared by and generate the Word report. Read the coverage section first — if it says access-port visibility, so will the client, and the rest of the report has to be written with that caveat.
- Click **Export evidence package**. The zip holds the JSON, the report, every export, every raw PCAP and a SHA-256 manifest — keep it with the engagement record; it is what you produce when a result is challenged. Verify any copy later with `sha256sum -c SHA256SUMS`.
- Clear prototype data only after the exports are safely stored.

## Scout Assist

- Scout Assist tab in the app, or `python3 copilot.py --database data/<file>.db`, at the end of a capture day. Ask it what to investigate first, which relationships cross a boundary without a decision, what to ask the controls engineer tomorrow, or to draft a finding from an unexpected path. It only sees evidence OT Scout already holds and must cite the record ids it used; the grounding pill (or the `[check]` line at the terminal) under every answer says whether every id, IP and MAC it mentioned traces back to supplied evidence. Treat an answer that fails that check as noise, and treat every answer as a suggestion — the assessor validates on site and owns the finding.
- Decide where the evidence may go before you ask. Settings (top right) says whether the chosen backend is local (evidence stays on the machine) or cloud (the evidence selected for each question — names, IPs, MACs, relationships — is sent to the provider). If the engagement letter or the customer's data rules do not allow that, use a local model. The API key lives in `data/copilot-settings.json` on the assessment machine and is never written to a database or an evidence package; "Forget saved key" removes it when you hand the machine over or finish the engagement.
- "Start a finding from this" pre-fills a finding from an answer. It arrives as a Draft with Scout Assist's words in Condition, Evidence and Recommendation — rewrite them in your own words against the evidence register before it goes anywhere near a report.
- On a slow laptop the first token can take a minute or more: the model has to read the evidence before it answers. Lower `--budget` (try 6000) for shorter prompts, or run the standard set with `--eval` while you do something else and read `data/copilot-log.jsonl` afterwards.

## Things that go wrong

- Tool shows "Can't reach the OT Scout server": the app on the collection laptop has stopped or the network between you and it has changed. Check the terminal it is running in.
- Lots of identities, few physical assets: locally-administered or virtual MACs. Normal on segments with VMs, HA pairs or LLDP-heavy switches; the inventory separates them.
- Many assets, no relationships: you are on an access port. Fix the mirror.
- Nothing at all: wrong interface selected, or the capture was started without root.
