"""Framework references for findings: IEC 62443 requirements and MITRE ATT&CK for ICS techniques.

Two small catalogues (ID → short name) plus a mapping from each auto-drafted observation to the
references it most directly bears on. The mapping is deliberately conservative: an evidence gap
gets the 62443 requirement it leaves unverified, but no ATT&CK technique — a missing SPAN port is
not an adversary behaviour. Assessors can add or remove references on any finding in the register.

IEC 62443-3-3 system requirements are cited as "SR x.y"; the two programme-level items that have no
3-3 equivalent (patching, backup/restore as a service capability) cite IEC 62443-2-4 practices.
"""

IEC62443 = {
    # FR 1 — Identification and authentication control
    "SR 1.1": "Human user identification and authentication",
    "SR 1.2": "Software process and device identification and authentication",
    "SR 1.3": "Account management",
    "SR 1.5": "Authenticator management",
    "SR 1.6": "Wireless access management",
    "SR 1.7": "Strength of password-based authentication",
    "SR 1.13": "Access via untrusted networks",
    # FR 2 — Use control
    "SR 2.1": "Authorization enforcement",
    "SR 2.2": "Wireless use control",
    "SR 2.3": "Use control for portable and mobile devices",
    "SR 2.6": "Remote session termination",
    "SR 2.8": "Auditable events",
    # FR 3 — System integrity
    "SR 3.1": "Communication integrity",
    "SR 3.2": "Malicious code protection",
    "SR 3.4": "Software and information integrity",
    "SR 3.8": "Session integrity",
    # FR 4 — Data confidentiality
    "SR 4.1": "Information confidentiality",
    "SR 4.3": "Use of cryptography",
    # FR 5 — Restricted data flow
    "SR 5.1": "Network segmentation",
    "SR 5.2": "Zone boundary protection",
    "SR 5.3": "General purpose person-to-person communication restrictions",
    "SR 5.4": "Application partitioning",
    # FR 6 — Timely response to events
    "SR 6.1": "Audit log accessibility",
    "SR 6.2": "Continuous monitoring",
    # FR 7 — Resource availability
    "SR 7.1": "Denial of service protection",
    "SR 7.3": "Control system backup",
    "SR 7.4": "Control system recovery and reconstitution",
    "SR 7.6": "Network and security configuration settings",
    "SR 7.7": "Least functionality",
    "SR 7.8": "Control system component inventory",
    # IEC 62443-2-4 service-provider practices (programme level)
    "2-4 SP.06": "Configuration management",
    "2-4 SP.07": "Remote access",
    "2-4 SP.11": "Patch management",
    "2-4 SP.12": "Backup / restore",
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
    """'SR 5.1' -> 'SR 5.1 Network segmentation'; unknown ids pass through unchanged."""
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
