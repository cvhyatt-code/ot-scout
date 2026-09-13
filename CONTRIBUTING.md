# Contributing

Short version: **issues are welcome, pull requests are not accepted.**

## Issues, yes

Bug reports, protocol decoding that comes out wrong, a capture scenario the tool handles badly, a
report section that doesn't survive contact with a real client — all genuinely useful. Open an issue.

What helps most:

- What you were doing, what you expected, what happened.
- The OT Scout version (header, startup line, or the About dialog).
- Your OS and Python version.
- For a decoding problem: a small PCAP that reproduces it, **with nothing confidential in it**. Do not
  attach a capture from a client's network. Trim it, synthesise it, or describe the frame structure
  instead. A bug report is not worth a confidentiality breach.

Feature suggestions are welcome too, with the caveat below about what this is.

## Pull requests, no

Not because contributions aren't valued — because of what accepting them would do to the licence.

OT Scout is AGPL-3.0-or-later, and the copyright is held by Higate Ventures LLC. Accepting outside
patches would split that copyright across everyone who contributed, and any future decision about
licensing would then need every one of their agreements. Keeping the copyright in one place keeps
those options open. A contributor licence agreement would solve it, but that is more ceremony than a
one-person tool deserves, and it puts people off for no good reason.

So pull requests will be closed unread. That is not a judgement on the patch.

## What you can do instead

The licence gives you a lot without needing anyone's permission:

- **Fork it and change it.** That is the point of the AGPL. Keep it under the same licence, say what
  you changed, and publish your source if you distribute it or let others reach it over a network.
- **Open an issue describing the fix.** A clear description of the bug and how you solved it in your
  fork is often faster to act on than a patch, and it costs you nothing.
- **Tell people your fork exists.** A well-maintained fork is a legitimate outcome, not a failure.

## What this project is

A point-in-time assessment tool built and maintained by one person alongside consulting work. It is
not a monitoring platform, it is not a product, and there is no support commitment. Issues are read
and acted on when there is time. If you need something with an SLA behind it, the commercial OT
monitoring platforms exist and are good at what they do.
