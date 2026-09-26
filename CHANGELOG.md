# OT Scout Community Edition changelog

## v1.0.0

First Community release.

- Passive capture from a live interface or an imported PCAP, with a PCAP saved per session.
- Decoders for ARP, Modbus/TCP, DNP3, S7comm, Profinet DCP, OPC UA and EtherNet/IP.
- Asset inventory with vendor lookup, fingerprints, manual override, identity merge and CSV import of
  documented assets.
- Communications map, Purdue zones and conduits with suggested levels, and a numbered band diagram.
- Findings register with drafts from the evidence, evidence links, and IEC 62443 and ATT&CK for ICS
  references.
- CSV export of inventory, relationships and findings, and a single self-contained HTML export.
- Binds 127.0.0.1:8767 by default. Every request needs the per-launch token printed at startup; Host and
  Origin are checked as well.
- Data lives in `~/.local/share/ot-scout/`, and follows `SUDO_USER` under sudo.
