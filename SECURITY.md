# Security

OT Scout runs as root on a laptop plugged into industrial networks, so vulnerabilities in it matter.
Reports are welcome.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose
**Report a vulnerability**. Please don't open a public issue for a security problem until it's fixed.

This is maintained by one person alongside other work. Expect an acknowledgement within about a week and
an assessment within about a month. If a report goes unanswered for a month, assume it was missed and feel
free to disclose publicly.

## Scope

In scope:

- **Frame and file parsing** (`parser.py`, `opcua.py`, `cip.py`, `capture.py`). These decode bytes that
  an attacker on the monitored network, or a hostile PCAP file, fully controls.
- **The web interface** (`web.py`, `bind.py`): a way around the launch token or the Host and Origin
  checks, path traversal, upload handling.
- **Anything that transmits on the capture interface**, under any circumstances.

Known and documented, not vulnerabilities:

- **Live capture runs the web server as root.** Privilege separation is planned for 1.1. Escalation
  *from* the tool to something it should not reach is in scope.
- **Captured data sits unencrypted** in `~/.local/share/ot-scout/`. Protecting the laptop is the
  operator's job.
