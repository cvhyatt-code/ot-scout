# Installing and running OT Scout

OT Scout is a point-in-time assessment tool. You install it on a laptop, take the laptop to a site, capture for a few hours or days, and leave with a report and an evidence package. It is not a monitoring platform and is not designed to be left installed.

## Will it run for me?

| | Live capture | Import a PCAP | Inventory, zones, findings, report |
|---|---|---|---|
| **Linux, as root** | Yes | Yes | Yes |
| **Linux, ordinary user** | No | Yes | Yes |
| **Windows / macOS** | No | Yes | Yes |

Live capture is Linux-only and needs root. It opens an `AF_PACKET` socket and sets Linux-specific socket options, which have no equivalent on Windows or macOS.

Everything *downstream* of capture is portable Python with no platform dependency. If someone else hands you a PCAP — a vendor, the plant's IT group, a previous visit — you can do the entire assessment on Windows or macOS: import it, build the inventory, place assets on the Purdue model, record conduit decisions, work the findings register, and generate the Word report. You just can't be the one holding the capture laptop.

Known rough edge: on Windows, pressing Start capture currently fails with an unhandled Python error rather than a clear message. Use the import path.

## What you need

**Software**

- Python 3.10 or newer. Nothing else. No pip install, no virtualenv, no third-party packages — the SQLite store, the web server and the .docx writer are all standard library.
- Linux (tested on Linux Mint and Ubuntu) if you want to capture.

**Hardware**

Any modern x86-64 laptop with an SSD is a reasonable starting point. Be honest with yourself about sizing rather than trusting a spec: the only measurement that matters is the drop counter on the Collect tab, and you won't know how your machine handles a particular mirror port until you point it at one. Start a short capture, watch the counters, and read the next section.

A wired gigabit NIC. A USB 3 gigabit adapter is fine and is often more convenient than the built-in port, since it leaves the built-in one free for you to keep working.

**Network access at the site**

A SPAN/mirror port or a network TAP at each place you want to collect. Without one, you are on an ordinary access port and will see broadcast traffic and your own — which OT Scout will tell you, on the Collect tab, as reduced visibility confidence. It does not pretend an access port saw the network.

What to ask the plant's network person for, in their words: *"a mirror/SPAN session on switch X, source = the VLANs or ports you care about, destination = the port my laptop is plugged into, receive-only."*

## Install

```bash
git clone https://github.com/cvhyatt-code/ot-scout.git
cd ot-scout
python3 -m unittest discover -s tests
sudo python3 run.py
```

Then open `http://127.0.0.1:8080`.

The test suite should pass with no failures before you take the tool to a site. If it doesn't, stop — something about the Python version or the checkout is wrong and you do not want to find that out in a plant.

Run it from the repository root. The app reads `CHANGELOG.md` and `ASSESSMENT_GUIDE.md` from there to serve the in-app About and Assessment guide links.

For analysis only — no capture — drop the `sudo`:

```bash
python3 run.py
```

Everything works except starting a live capture.

**Flags**

| Flag | Default | What it does |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address for the web UI. See *Reaching the UI* before changing this. |
| `--port` | `8080` | Web UI port. |
| `--database` | `data/ot_scout_v4.db` | SQLite database. One per engagement is a good habit. |

**See it before you use it.** Click **Load demo data** in the header. It builds a fictitious water utility — Riverbend Regional Water Utility — with captures, decoded fingerprints, a walkdown inventory, Purdue placement, conduit decisions and findings, so you can walk every tab without a plant. Your own database is untouched; **Back to my data** switches back.

## Why root, and what you lose without it

Two things, not one.

1. **The raw socket.** `AF_PACKET` requires it. Without root you get "Packet capture permission denied."
2. **The receive buffer.** OT Scout asks the kernel for a 64 MB socket receive buffer using `SO_RCVBUFFORCE`, which only root may use. Fall back to ordinary `SO_RCVBUF` and the kernel silently caps you at `net.core.rmem_max`, about 200 KB by default — which fills in milliseconds on a busy mirror port, and every frame after that is gone.

The buffer OT Scout actually got is reported in the capture status, so you can confirm you have what you think you have.

## Running a capture, and reading the counters

Capture runs on two threads by design. A reader thread does almost nothing per frame — receive it, write it to the raw PCAP, hand it to a queue — because every microsecond spent in that loop is receive-buffer time. A parser thread drains the queue into the database. The throttle on the Collect tab paces the parser, never the reader.

That split means **two different counters can climb, and they mean opposite things.**

| Counter | What happened | What to do |
|---|---|---|
| **Dropped** | The kernel discarded frames because the receive buffer filled. Those frames are gone for good. | Narrow the SPAN to fewer source ports or VLANs. Failing that, capture with `dumpcap -B 512` and import the file afterwards. Failing that, better hardware. |
| **Unparsed** | The parser fell behind and the queue (300,000 frames) filled. The frames are safe in the raw PCAP — they simply weren't parsed live. | Nothing urgent. Re-import that session's PCAP afterwards to pick them up. |
| **Malformed** | The decoder raised on the frame and OT Scout skipped it rather than letting one frame stop the capture. The frame is in the raw PCAP. | Normally nothing — truncated or corrupt frames happen. A steady stream of them on one segment is worth a look at the PCAP in Wireshark. |

Dropped frames make the inventory for that session incomplete in a way nobody can quantify, which is why the report raises an amber callout in the coverage section when any session dropped frames. Unparsed frames are recoverable, so they don't.

**One thing at a time.** OT Scout refuses, with a clear message, to import a PCAP, reset the database, update the vendor table or switch data sets while a capture is running. That is deliberate — those operations compete with the live capture for CPU and for SQLite, and that contention is exactly what produces dropped frames. Stop the capture first.

## Importing a PCAP

Use the import control on the Collect tab. It becomes its own session, with visibility marked unknown because OT Scout has no way to know how the file was captured.

Two constraints worth knowing before you're standing in a plant:

- **Classic libpcap format only, Ethernet link type.** Modern Wireshark and `dumpcap` write **pcapng** by default, which OT Scout rejects. Convert first:
  ```bash
  editcap -F libpcap capture.pcapng capture.pcap    # convert an existing file
  dumpcap -P -i eth0 -w capture.pcap                # or capture in pcap format to begin with
  ```
- **512 MB per file**, and the file is read into memory during import. On a laptop with 8 GB, a 512 MB PCAP is not a comfortable operation. Split large captures:
  ```bash
  editcap -c 500000 big.pcap chunk.pcap             # split by packet count
  ```

## Reaching the UI

**The web interface has no authentication.** Anyone who can reach the port can export the entire evidence package for the engagement, write the model API key, or reset the database. There are no accounts, no password, no token.

That is a deliberate choice for a tool bound to localhost on the assessor's own laptop, and it is the reason the default bind address is `127.0.0.1`.

So: **do not use `--host 0.0.0.0` on a plant network.** Putting an unauthenticated control plane for a live OT assessment onto the network you are assessing is not a thing to do casually, and it undercuts the "we never touch anything" position you took to get the engagement.

If you need to reach the capture box remotely — it's running in a control room and you're not — put authentication in front of it rather than removing the one protection it has. A private overlay network works well:

```bash
tailscale serve --bg --https=8443 8080
```

The app still binds localhost only; Tailscale terminates TLS and does the authentication the app doesn't. Reach it at your tailnet name from any device signed into your tailnet.

Whatever you use, the rule is the same: something must authenticate before the request reaches OT Scout.

## Getting the data off

Everything is on the Report tab.

| Output | What it is |
|---|---|
| **Word report** | The client deliverable: cover, executive readout, coverage, inventory, communications, zones, findings register with IEC 62443 and ATT&CK for ICS references, roadmap, appendices. |
| **Evidence package (zip)** | Everything needed to check the work — see below. |
| **CSV exports** | Assets, relationships, discovery traffic, flows. |
| **`purdue-zones.svg`** | The zone and conduit diagram, as vector. |
| **`assessment.json`** | The full evidence export. |

The evidence package contains `assessment.json`, `report.docx`, the four CSVs, `purdue-zones.svg`, the raw PCAP of every live session, and two manifests: `MANIFEST.txt` (human-readable, with per-session frame and drop counts) and `SHA256SUMS` (machine-readable). Anyone can verify nothing changed since you handed it over:

```bash
unzip ot-scout-evidence-package.zip -d evidence
cd evidence && sha256sum -c SHA256SUMS
```

The report can be re-rendered later from the JSON alone, with no database and no app running:

```bash
python3 -m ot_scout.report assessment.json report.docx
```

## Where your data lives, and cleaning up

Everything sits next to the database, under `data/` by default:

| Path | Contents |
|---|---|
| `data/ot_scout_v4.db` | The assessment: assets, relationships, sites, zones, findings. |
| `data/captures/` | Raw PCAPs, one per live session. These are the largest files and the most sensitive. |
| `data/copilot-settings.json` | Scout Assist model connection, **including the API key**. Mode 0600. |
| `data/copilot-log.jsonl` | Scout Assist question and answer log. |
| `data/demo.db` | The fictitious demo data set. Not yours; safe to ignore. |

The whole `data/` directory is git-ignored, so nothing here is ever committed.

**If you use a cloud backend for Scout Assist**, the evidence selected for each question — device names, IP addresses, MAC addresses, relationships — is sent to that provider. On engagements where customer data may not leave the site, use a local backend (Ollama or llama.cpp) instead. The key is stored on that machine only and never enters a database or an evidence package.

**When the engagement ends**, you are holding a full passive recording of a customer's OT network on a laptop. Handle it the way your contract says to: deliver the evidence package, then remove `data/` from the laptop, or wipe the machine. Decide this before the engagement, not after.

## Authorization

OT Scout transmits nothing. It never sends a frame, never probes, never queries a device, never holds credentials for anything. That is a real and defensible position when someone asks whether your laptop is a risk to the process.

It is not a substitute for permission. Capturing traffic on a plant network is still an activity that needs the asset owner's authorization, and in most environments a change record. Get it in writing before you plug anything in.
