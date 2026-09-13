# Security

OT Scout is a security assessment tool that runs with root on a laptop plugged into industrial
networks. Vulnerabilities in it matter. Reports are welcome.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: go to the **Security** tab of this repository and
choose **Report a vulnerability**. That opens a private advisory visible only to the maintainer.

Please do not open a public issue for a security problem until it has been fixed.

## What to expect

This is a one-person project maintained alongside other work. Being honest about that rather than
publishing a response time nobody will meet:

- Acknowledgement within about a week.
- An assessment of whether it is real, and a rough timeline, within about a month.
- Credit in the changelog when a fix ships, unless you would rather not be named.

If a report goes unanswered for a month, assume it was missed rather than ignored, and feel free to
disclose publicly.

## Scope

In scope, and most interesting:

- **Frame and file parsing.** `ot_scout/parser.py`, `opcua.py`, `cip.py` and `capture.py` decode
  bytes that an attacker on the monitored network, or a hostile PCAP file, fully controls. Crashes,
  hangs, unbounded memory growth and anything worse all count.
- **The web interface.** `ot_scout/web.py` — path traversal, upload handling, evidence-package
  construction, anything that escapes the intended file boundaries.
- **Anything that transmits.** OT Scout's core claim is that it never sends a frame on the capture
  interface. A code path that transmits, under any circumstances, is a serious bug independent of
  whether it is exploitable.
- **Evidence integrity.** A way to make the SHA-256 manifest disagree with what is actually in the
  evidence package.
- **Scout Assist grounding.** A way to get content from a captured network to influence the model's
  answer such that the grounding check does not catch it.

Known and documented, not vulnerabilities:

- **The web interface has no authentication.** It binds to loopback and refuses a non-loopback bind
  unless `--insecure-bind` is passed explicitly. This is a deliberate design choice for a
  single-operator laptop tool; see `INSTALL.md`. A bypass *of the bind guard* is in scope. The
  absence of a login is not.
- **Live capture requires root.** Raw packet capture needs it. Privilege escalation *from* OT Scout
  to something it should not reach is in scope; the fact that it runs as root is not.
- **Captured data sits unencrypted on the assessor's disk** under `data/`. Handling that is the
  operator's job and is documented in `INSTALL.md`.
