"""Framework references for findings: IEC 62443 requirements and MITRE ATT&CK for ICS techniques.

Two small catalogues (ID → short name) plus a mapping from each auto-drafted observation to the
references it most directly bears on. The mapping is deliberately conservative: an evidence gap
gets the 62443 requirement it leaves unverified, but no ATT&CK technique — a missing SPAN port is
not an adversary behaviour. Assessors can add or remove references on any finding in the register.

IEC 62443-3-3 system requirements are cited as "SR x.y"; the programme-level items that have no 3-3
equivalent (patching, backup/restore as a service capability) cite IEC 62443-2-4 practices. The
identifiers are the citation; the short names beside them are this project's own plain-English
paraphrases, not the standard's clause titles. Refer to the standard itself for the normative text.
"""

IEC62443 = {
    # FR 1 — identification and authentication control
    "SR 1.1": "Users are identified and authenticated",
    "SR 1.2": "Devices and software processes are identified and authenticated",
    "SR 1.3": "Accounts are managed across their lifecycle",
    "SR 1.5": "Credentials and keys are managed",
    "SR 1.6": "Wireless access is controlled",
    "SR 1.7": "Passwords meet a defined strength",
    "SR 1.13": "Access from untrusted networks is controlled",
    # FR 2 — use control
    "SR 2.1": "Permissions are enforced per user and role",
    "SR 2.2": "Wireless use is limited to approved purposes",
    "SR 2.3": "Portable and mobile devices are controlled",
    "SR 2.6": "Idle remote sessions are terminated",
    "SR 2.8": "Security-relevant events are recorded",
    # FR 3 — system integrity
    "SR 3.1": "Traffic is protected against tampering in transit",
    "SR 3.2": "Protection against malicious code",
    "SR 3.4": "Software and configuration integrity is verified",
    "SR 3.8": "Sessions are protected against hijacking",
    # FR 4 — data confidentiality
    "SR 4.1": "Sensitive information is protected from disclosure",
    "SR 4.3": "Cryptography is applied and managed properly",
    # FR 5 — restricted data flow
    "SR 5.1": "The network is divided into zones",
    "SR 5.2": "Traffic crossing a zone boundary is controlled",
    "SR 5.3": "General-purpose messaging is restricted in control zones",
    "SR 5.4": "Applications are kept in separate partitions",
    # FR 6 — timely response to events
    "SR 6.1": "Audit records are available for review",
    "SR 6.2": "The environment is monitored continuously",
    # FR 7 — resource availability
    "SR 7.1": "Resistance to denial-of-service conditions",
    "SR 7.3": "Control-system configuration is backed up",
    "SR 7.4": "The control system can be restored after failure",
    "SR 7.6": "Network and security settings match a known baseline",
    "SR 7.7": "Only required functions and services are enabled",
    "SR 7.8": "A component inventory is maintained",
    # IEC 62443-2-4 service-provider practices (programme level)
    "2-4 SP.06": "Service-provider configuration management",
    "2-4 SP.07": "Controlled remote access by the service provider",
    "2-4 SP.11": "Patches are assessed and applied",
    "2-4 SP.12": "Backup and restore capability",
}

ATTACK_ICS = {
    "T0812": "Default Credentials",
    "T0822": "External Remote Services",
    "T0826": "Loss of Availability",
    "T0830": "Adversary-in-the-Middle",
    "T0836": "Modify Parameter",
    "T0842": "Network Sniffing",
    "T0843": "Program Download",
    "T0846": "Remote System Discovery",
    "T0855": "Unauthorized Command Message",
    "T0859": "Valid Accounts",
    "T0866": "Exploitation of Remote Services",
    "T0869": "Standard Application Layer Protocol",
    "T0882": "Theft of Operational Information",
    "T0883": "Internet Accessible Device",
    "T0884": "Connection Proxy",
    "T0886": "Remote Services",
    "T0888": "Remote System Information Discovery",
    "T0890": "Exploitation for Privilege Escalation",
    "T0809": "Data Destruction",
}

# Auto-drafted observation title → (IEC 62443 refs, ATT&CK for ICS refs)
DRAFT_MAPPING = {
    "Passive visibility is inadequate for inventory completeness": (["SR 7.8", "SR 6.2"], []),
    "Network legs without an evidence source": (["SR 7.8"], []),
    "Asset identity and context require drawing and walkdown reconciliation": (["SR 7.8"], []),
    "External communication pathways require policy validation": (["SR 5.1", "SR 5.2", "SR 1.13"], ["T0883", "T0822", "T0886"]),
    "Multiple IPv4 subnets observed on the same Layer-2 segment": (["SR 5.1", "SR 7.6"], ["T0846", "T0884"]),
    "Communications marked unexpected against the conduit baseline": (["SR 5.1", "SR 5.2", "SR 2.1"], ["T0886", "T0866", "T0855"]),
    "Direct OT-to-enterprise communications bypass the industrial DMZ": (["SR 5.1", "SR 5.2", "SR 5.4"], ["T0886", "T0866", "T0859"]),
    "OT assets communicate directly with external or internet endpoints": (["SR 5.1", "SR 5.2", "SR 5.4"], ["T0883", "T0822", "T0886"]),
    "Boundary-crossing communications not yet reviewed against a conduit baseline": (["SR 5.1", "SR 5.2"], []),
    "Purdue level not assigned for all physical assets": (["SR 5.1", "SR 7.8"], []),
    "End-of-life or end-of-support OT assets in service": (["2-4 SP.11", "SR 7.8"], ["T0866", "T0890"]),
    "Controller and application backups missing or unverified": (["SR 7.3", "SR 7.4", "2-4 SP.12"], ["T0809", "T0826"]),
    "Cleartext management or file-transfer protocols observed": (["SR 4.1", "SR 4.3", "SR 1.5"], ["T0842", "T0859"]),
    "OPC UA endpoints allow unencrypted or anonymous sessions": (["SR 1.1", "SR 1.2", "SR 3.1", "SR 4.3"], ["T0842", "T0859", "T0855", "T0830"]),
    "Industrial protocols observed; conduit approval baseline not yet established": (["SR 5.1", "SR 3.1", "SR 2.1"], ["T0855", "T0836", "T0869"]),
    "Raw evidence is retained separately from normalized relationships and inferences": ([], []),
}


def describe(ref: str) -> str:
    """'SR 5.1' -> 'SR 5.1 The network is divided into zones'; unknown ids pass through unchanged."""
    ref = ref.strip()
    name = IEC62443.get(ref) or ATTACK_ICS.get(ref)
    return f"{ref} {name}" if name else ref


def format_refs(refs: list[str]) -> str:
    return "; ".join(describe(r) for r in refs if r.strip())


def refs_for(title: str) -> dict:
    """References for an auto-drafted observation, as the two text fields the register stores."""
    iec, attack = DRAFT_MAPPING.get(title, ([], []))
    return {"iec62443": format_refs(iec), "attack": format_refs(attack)}


def catalogue() -> dict:
    """For the UI: id → name, both frameworks."""
    return {"iec62443": dict(IEC62443), "attack": dict(ATTACK_ICS)}
