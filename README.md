# OT Scout Community Edition

A passive OT/ICS assessment tool: plug a laptop into a mirror port, capture what the plant network is
already saying, and turn it into an asset inventory, a communications map, a Purdue zone and conduit
diagram and a findings register, without ever sending a packet onto that network.

It is an assessment aid for an authorized engagement, not a monitoring platform. Discovery results are
evidence, not proof of complete coverage: inactive, encrypted, non-IP and unmonitored devices still need
drawings, customer records and a physical walkdown.

A commercial edition with additional features exists.

## What it does

- **Passive capture.** Live capture from a SPAN/mirror port or TAP, with Start/Stop, a capture timer and
  a PCAP saved per session. Or import a classic libpcap file someone else captured.
- **Protocol decoders.** ARP, Modbus/TCP, DNP3, Siemens S7comm, Profinet DCP, OPC UA and EtherNet/IP,
  plus DHCP, DNS, LLDP, HTTP, BACnet and the usual IT protocols for context.
- **Asset inventory.** IEEE OUI vendor lookup, protocol fingerprints, manual override, infrastructure
  classification, merging two identities into one asset, and a CSV template for documented assets the
  capture cannot see.
- **Communications.** One row per device pair, with every flow folded in, labelled by the Purdue
  boundary it crosses. Broadcast and service-discovery traffic is kept separate.
- **Zones and conduits.** Purdue level per asset (suggested from protocol role, confirmed by you), a
  zone-pair rollup and a numbered band diagram, with an Approved / Tolerated / Unexpected decision on
  each conduit.
- **Findings.** A register with drafts generated from the evidence, links to the evidence each finding
  cites, and IEC 62443 and MITRE ATT&CK for ICS references.
- **Export.** CSV of the inventory, relationships and findings, and a single self-contained HTML file.

## Passive means passive

Capture opens a raw socket on the chosen interface in promiscuous mode and reads frames. There is no code
path that transmits on it: no scanning, no probing, no queries to any device. The one thing that leaves the
machine, and only when you ask, is **Update IEEE vendors**, which downloads the IEEE OUI registry over HTTPS.

## Requirements

- Linux. Live capture needs root; nothing else does.
- Python 3.10 or later. No third-party packages.
- A SPAN/mirror port or a network TAP at each collection point, if you want more than broadcast traffic.

## Run it

```bash
git clone https://github.com/cvhyatt-code/ot-scout.git
cd ot-scout
python3 -m unittest discover -s tests
python3 run.py --demo          # the fictitious demo data set, no sudo needed
sudo python3 run.py            # for live capture
```

`run.py` prints a URL with a token in it, for example `http://localhost:8767/?token=…`. Open that URL,
token included, in your browser. Each launch has a new token.

- **Port and binding.** Port 8767, bound to 127.0.0.1. `--port` changes the port. `--host` changes the
  bind address and prints a warning when it is not loopback.
- **Data.** Everything is kept in `~/.local/share/ot-scout/`, outside the program folder. Under `sudo`,
  that is the invoking user's folder, and the files are handed back to that user. `--data-dir` puts it
  somewhere else.
- **Demo.** `--demo` opens the fictitious Riverbend Regional Water Utility data set, building it first if
  needed. Every name, address and finding in it is invented.

## Known limits

- **Live capture runs the whole web server as root.** Dropping privileges once the capture socket is
  open, or using `setcap cap_net_raw`, is planned for 1.1.
- Live capture is Linux only. PCAP import and everything after it run anywhere Python does.
- pcapng is not read. Convert with `editcap -F libpcap in.pcapng out.pcap`.

## Issues, contributions and security

Issues are welcome. Pull requests from outside contributors aren't accepted at this time. See
[`CONTRIBUTING.md`](CONTRIBUTING.md). To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

OT Scout Community Edition is free software under the **GNU Affero General Public License, version 3
or later**. The full text is in [`LICENSE`](LICENSE); copyright holders and third-party attributions
(MITRE ATT&CK for ICS, IEC 62443, the IEEE OUI registry) are in [`NOTICE`](NOTICE).

It is distributed WITHOUT ANY WARRANTY, express or implied. See sections 15 and 16 of the licence.

**Use it only where you are authorized to.** Capturing traffic on a plant network needs the asset
owner's permission and, in most environments, a change record. You are responsible for having it.
