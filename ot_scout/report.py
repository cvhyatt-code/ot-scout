"""Dependency-free .docx report generator for OT Scout.

Renders the assessment report structure (cover, document control, executive readout,
scope/evidence, coverage, inventory, communications, auto-generated observations, roadmap
and appendices) directly from the evidence in the store. Every number in the report comes
from data; narrative text is templated and clearly marked where assessor validation is
required. No third-party packages: the .docx is assembled as raw WordprocessingML.
"""
from __future__ import annotations

import io
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

try:
    from .frameworks import refs_for
except ImportError:  # run as a script: python3 ot_scout/report.py
    from frameworks import refs_for

INK = "16212B"
MUTED = "617181"
BLUE = "176B87"
NAVY = "112D3A"
LINE = "D9E1E7"
TILE = "E9EFF3"
AMBER_BG, AMBER = "FFF7D6", "9A6700"
RED_BG, RED = "FDE8E6", "B42318"
GREEN_BG, GREEN = "E3F5EA", "18794E"
BLUE_BG = "E3F0F5"

OT_PROTOCOLS = {
    "MODBUS-TCP": "Modbus/TCP", "DNP3": "DNP3", "OPC-UA": "OPC UA", "S7COMM": "Siemens S7comm",
    "ETHERNET-IP": "EtherNet/IP (explicit)", "ETHERNET-IP-IO": "EtherNet/IP (implicit I/O)",
    "BACNET-IP": "BACnet/IP", "MQTT": "MQTT", "MQTT-TLS": "MQTT over TLS",
    "PROFINET-DCP": "Profinet DCP (discovery)", "PROFINET-RT": "Profinet RT (cyclic I/O)",
}
IT_SERVICE_PROTOCOLS = {
    "SMB": "SMB/CIFS", "RDP": "RDP", "VNC": "VNC", "SSH": "SSH", "TELNET": "Telnet", "FTP": "FTP",
    "TFTP": "TFTP", "SNMP": "SNMP", "HTTP": "HTTP (cleartext)", "HTTPS": "HTTPS", "NTP": "NTP",
    "SYSLOG": "Syslog", "LDAP": "LDAP", "MS-RPC": "MS-RPC",
}
CLEARTEXT_RISK = {"TELNET", "FTP", "HTTP", "SNMP", "VNC", "TFTP"}


# ----------------------------------------------------------------------------- helpers
def fmt_int(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value or "")


def fmt_duration_words(seconds) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    return f"{minutes}m {secs}s"


def sanitize_mac(mac: str) -> str:
    parts = (mac or "").upper().split(":")
    if len(parts) != 6:
        return mac
    return ":".join(parts[:3] + ["XX", "XX", parts[5]])


def _duration_seconds(started: str, ended: str | None) -> int | None:
    try:
        start = datetime.fromisoformat(started)
        end = datetime.fromisoformat(ended) if ended else datetime.now(timezone.utc)
        return max(0, int((end - start).total_seconds()))
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- XML builder
class Doc:
    """Minimal WordprocessingML writer: paragraphs, headings, bullets, tables, callouts, tiles."""

    PAGE_W = 12240  # letter, twips
    MARGIN = 1080   # 0.75in
    TEXT_W = PAGE_W - 2 * MARGIN

    def __init__(self):
        self.body: list[str] = []

    # -- runs and paragraphs
    @staticmethod
    def run(text, bold=False, italic=False, color=None, size=None, caps=False) -> str:
        props = []
        if bold: props.append("<w:b/>")
        if italic: props.append("<w:i/>")
        if caps: props.append("<w:caps/>")
        if color: props.append(f'<w:color w:val="{color}"/>')
        if size: props.append(f'<w:sz w:val="{size * 2}"/><w:szCs w:val="{size * 2}"/>')
        rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
        parts = str(text).split("\n")
        body = '<w:br/>'.join(f'<w:t xml:space="preserve">{escape(p)}</w:t>' for p in parts)
        return f"<w:r>{rpr}{body}</w:r>"

    @staticmethod
    def _p(runs: str, style=None, align=None, before=None, after=None, shade=None, keep_next=False, numbered=None) -> str:
        props = []
        if style: props.append(f'<w:pStyle w:val="{style}"/>')
        if keep_next: props.append("<w:keepNext/>")
        if numbered is not None: props.append(f'<w:numPr><w:ilvl w:val="0"/><w:numId w:val="{numbered}"/></w:numPr>')
        if shade: props.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>')
        if before is not None or after is not None:
            props.append(f'<w:spacing w:before="{before or 0}" w:after="{after if after is not None else 120}"/>')
        if align: props.append(f'<w:jc w:val="{align}"/>')
        ppr = f"<w:pPr>{''.join(props)}</w:pPr>" if props else ""
        return f"<w:p>{ppr}{runs}</w:p>"

    def para(self, text="", style=None, **kw):
        runs = text if isinstance(text, str) and text.startswith("<w:r>") else self.run(text)
        self.body.append(self._p(runs, style=style, **kw))

    def runs(self, *runs, style=None, **kw):
        self.body.append(self._p("".join(runs), style=style, **kw))

    def h1(self, text): self.para(text, "Heading1", keep_next=True)
    def h2(self, text): self.para(text, "Heading2", keep_next=True)
    def h3(self, text): self.para(text, "Heading3", keep_next=True)
    def bullet(self, text): self.body.append(self._p(self.run(text), style="ListParagraph", numbered=1, after=60))
    def muted(self, text): self.runs(self.run(text, color=MUTED, size=9), after=160)
    def page_break(self): self.body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
    def labeled(self, label, text): self.runs(self.run(label + ": ", bold=True), self.run(text), after=80)

    # -- tables
    @staticmethod
    def _cell(content: str, width: int, shade=None, borders=None, vmerge=None) -> str:
        props = [f'<w:tcW w:w="{width}" w:type="dxa"/>']
        if borders: props.append(borders)
        if shade: props.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>')
        props.append('<w:tcMar><w:top w:w="70" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="70" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>')
        return f"<w:tc><w:tcPr>{''.join(props)}</w:tcPr>{content}</w:tc>"

    def table(self, header: list[str], rows: list[list], widths: list[float] | None = None, size=9, header_shade=TILE):
        cols = len(header)
        widths = widths or [1 / cols] * cols
        tw = [int(self.TEXT_W * w) for w in widths]
        grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in tw)
        border = "".join(f'<w:{edge} w:val="single" w:sz="4" w:space="0" w:color="{LINE}"/>' for edge in ("top", "left", "bottom", "right", "insideH", "insideV"))
        out = [f'<w:tbl><w:tblPr><w:tblW w:w="{self.TEXT_W}" w:type="dxa"/><w:tblBorders>{border}</w:tblBorders><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>{grid}</w:tblGrid>']
        head_cells = "".join(self._cell(self._p(self.run(h, bold=True, size=size, color=INK), after=0), tw[i], shade=header_shade) for i, h in enumerate(header))
        out.append(f"<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>{head_cells}</w:tr>")
        for row in rows:
            cells = []
            for i, value in enumerate(row):
                if isinstance(value, tuple):  # (text, color) or (text, color, bold)
                    text, color = value[0], value[1]
                    bold = value[2] if len(value) > 2 else False
                    content = self._p(self.run(text, size=size, color=color, bold=bold), after=0)
                elif isinstance(value, list):  # multiple lines: first bold, rest muted
                    content = self._p(self.run(value[0], size=size, bold=True), after=0) + "".join(self._p(self.run(v, size=size - 1, color=MUTED), after=0) for v in value[1:] if v)
                else:
                    content = self._p(self.run(value, size=size), after=0)
                cells.append(self._cell(content, tw[i]))
            out.append(f"<w:tr><w:trPr><w:cantSplit/></w:trPr>{''.join(cells)}</w:tr>")
        out.append("</w:tbl>")
        self.body.append("".join(out))
        self.body.append(self._p("", after=120))

    def callout(self, label: str, text: str, fill=AMBER_BG, accent=AMBER):
        border = f'<w:tcBorders><w:top w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/><w:left w:val="single" w:sz="24" w:space="0" w:color="{accent}"/></w:tcBorders>'
        content = self._p(self.run(label.upper() + "  ", bold=True, size=9, color=accent) + self.run(text, size=10), after=0)
        self.body.append(f'<w:tbl><w:tblPr><w:tblW w:w="{self.TEXT_W}" w:type="dxa"/><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid><w:gridCol w:w="{self.TEXT_W}"/></w:tblGrid><w:tr><w:trPr><w:cantSplit/></w:trPr>{self._cell(content, self.TEXT_W, shade=fill, borders=border)}</w:tr></w:tbl>')
        self.body.append(self._p("", after=120))

    def tiles(self, items: list[tuple[str, str]]):
        n = len(items)
        w = self.TEXT_W // n
        border = f'<w:tcBorders><w:top w:val="single" w:sz="4" w:color="{LINE}"/><w:bottom w:val="single" w:sz="4" w:color="{LINE}"/><w:left w:val="single" w:sz="4" w:color="FFFFFF"/><w:right w:val="single" w:sz="4" w:color="FFFFFF"/></w:tcBorders>'
        cells = []
        for value, caption in items:
            content = self._p(self.run(value, bold=True, size=22, color=NAVY), align="center", after=0) + self._p(self.run(caption, size=8, color=MUTED, caps=True), align="center", after=0)
            cells.append(self._cell(content, w, shade=TILE, borders=border))
        grid = "".join(f'<w:gridCol w:w="{w}"/>' for _ in items)
        self.body.append(f'<w:tbl><w:tblPr><w:tblW w:w="{self.TEXT_W}" w:type="dxa"/><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>{grid}</w:tblGrid><w:tr><w:trPr><w:cantSplit/></w:trPr>{"".join(cells)}</w:tr></w:tbl>')
        self.body.append(self._p("", after=120))

    # -- packaging
    def build(self, title: str, author: str, footer_text: str) -> bytes:
        sect = (f'<w:sectPr><w:footerReference w:type="default" r:id="rIdFooter"/>'
                f'<w:pgSz w:w="{self.PAGE_W}" w:h="15840"/><w:pgMar w:top="1080" w:right="{self.MARGIN}" w:bottom="1080" w:left="{self.MARGIN}" w:header="540" w:footer="540" w:gutter="0"/></w:sectPr>')
        ns = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
              'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')
        document = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {ns}><w:body>{"".join(self.body)}{sect}</w:body></w:document>'
        footer = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr {ns}><w:p><w:pPr><w:pStyle w:val="Footer"/><w:jc w:val="right"/></w:pPr>'
                  f'{self.run(footer_text + "   Page ", size=8, color=MUTED)}'
                  f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{MUTED}"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{MUTED}"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{MUTED}"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r>'
                  f'{self.run(" of ", size=8, color=MUTED)}'
                  f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{MUTED}"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{MUTED}"/></w:rPr><w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="{MUTED}"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r>'
                  f'</w:p></w:ftr>')
        styles = STYLES_XML
        numbering = NUMBERING_XML
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        core = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                f'<dc:title>{escape(title)}</dc:title><dc:creator>{escape(author)}</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified></cp:coreProperties>')
        content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                         '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                         '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
                         '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
                         '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
                         '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>')
        rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>')
        doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                    '<Relationship Id="rIdNumbering" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>'
                    '<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", rels)
            z.writestr("word/document.xml", document)
            z.writestr("word/styles.xml", styles)
            z.writestr("word/numbering.xml", numbering)
            z.writestr("word/footer1.xml", footer)
            z.writestr("word/_rels/document.xml.rels", doc_rels)
            z.writestr("docProps/core.xml", core)
        return buf.getvalue()


STYLES_XML = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:color w:val="{INK}"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="52"/><w:szCs w:val="52"/><w:color w:val="{NAVY}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="360"/></w:pPr><w:rPr><w:sz w:val="26"/><w:szCs w:val="26"/><w:color w:val="{BLUE}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:pageBreakBefore/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="4" w:color="{BLUE}"/></w:pBdr><w:spacing w:before="0" w:after="200"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="34"/><w:szCs w:val="34"/><w:color w:val="{NAVY}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="100"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/><w:szCs w:val="26"/><w:color w:val="{BLUE}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/><w:szCs w:val="22"/><w:color w:val="{INK}"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="360"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/></w:style>
</w:styles>'''

NUMBERING_XML = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="360" w:hanging="220"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr></w:lvl></w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>'''


# ----------------------------------------------------------------------------- data model
def collect(store, coverage=None) -> dict:
    """Snapshot everything the report needs from a Store (same shape as the JSON export plus coverage)."""
    assets = store.assets()
    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "summary": store.dashboard(),
            "sessions": store.sessions(), "assets": assets, "relationships": store.relationships(100000, assets),
            "discovery_traffic": store.discovery_traffic(100000), "flows": store.connections(100000),
            "sites": store.sites(), "findings": store.findings(), "zones": store.zone_summary(assets),
            "coverage": coverage or store.coverage()}


def derive_coverage(data: dict) -> dict:
    if data.get("coverage"):
        return data["coverage"]
    sessions = data.get("sessions") or []
    if not sessions:
        return {"level": "none", "message": "No collection has been performed."}
    latest = sessions[0]
    if latest.get("source_type") == "pcap":
        return {"level": "unknown", "message": "Imported PCAP visibility depends on its original capture point."}
    if latest.get("third_party_unicast", 0) >= 10:
        return {"level": "likely-mirror", "message": f"Third-party unicast traffic observed ({latest['third_party_unicast']} frames). Mirror/TAP visibility is likely, but coverage still requires validation."}
    if latest.get("packets"):
        return {"level": "limited", "message": "No meaningful third-party unicast traffic observed. This appears to be an ordinary access port or limited feed; inventory is incomplete."}
    return {"level": "none", "message": "No packets observed. Verify the interface, cabling and capture point."}


class Analysis:
    """Everything derived from the data, computed once so sections stay consistent."""

    def __init__(self, data: dict, sanitize: bool):
        self.data = data
        self.sanitize = sanitize
        self.summary = data.get("summary") or {}
        self.sessions = data.get("sessions") or []
        self.assets = data.get("assets") or []
        self.relationships = data.get("relationships") or []
        self.discovery = data.get("discovery_traffic") or []
        self.flows = data.get("flows") or []
        self.coverage = derive_coverage(data)
        self.site_records = data.get("sites") or []
        self.legs = [dict(leg, site=site.get("name", "")) for site in self.site_records for leg in (site.get("legs") or [])]
        self.legs_no_evidence = [l for l in self.legs if l.get("evidence_source") == "None yet" or l.get("status") in ("Planned", "Not accessible")]
        self.checklist_status: dict[str, list] = {}
        for site in self.site_records:
            for item in site.get("checklist") or []:
                self.checklist_status.setdefault(item["item"], []).append((site.get("name", ""), item))
        for s in self.sessions:
            if s.get("duration_seconds") is None:
                s["duration_seconds"] = _duration_seconds(s.get("started_at", ""), s.get("ended_at"))
        self.live_sessions = [s for s in self.sessions if s.get("source_type", "live") == "live"]
        self.total_duration = sum((s["duration_seconds"] or 0) for s in self.live_sessions)
        self.packets = sum(int(s.get("packets") or 0) for s in self.sessions)
        self.bytes = sum(int(s.get("bytes") or 0) for s in self.sessions)
        self.third_party = sum(int(s.get("third_party_unicast") or 0) for s in self.sessions)
        self.local_unicast = sum(int(s.get("local_unicast") or 0) for s in self.sessions)
        self.broadcast = sum(int(s.get("broadcast_multicast") or 0) for s in self.sessions)
        self.physical = [a for a in self.assets if a.get("physical_asset")]
        self.derived = [a for a in self.assets if not a.get("physical_asset")]
        self.access_methods = sorted({s.get("access_method", "") for s in self.sessions if s.get("access_method")})
        self.points = sorted({s.get("collection_point", "") for s in self.sessions})
        self.assessment_names = sorted({s.get("assessment", "") for s in self.sessions})
        self.sites = sorted({s.get("site", "") for s in self.sessions})
        self.categories: dict[str, dict] = {}
        for r in self.relationships:
            c = self.categories.setdefault(r.get("category", "Unicast"), {"count": 0, "packets": 0})
            c["count"] += 1; c["packets"] += int(r.get("packets") or 0)
        self.protocols: dict[str, dict] = {}
        for f in self.flows:
            p = self.protocols.setdefault(f.get("app_protocol") or "?", {"flows": 0, "packets": 0, "scope": set()})
            p["flows"] += 1; p["packets"] += int(f.get("packets") or 0); p["scope"].add(f.get("traffic_scope") or "")
        self.ot_seen = {k: v for k, v in self.protocols.items() if k in OT_PROTOCOLS}
        self.cleartext_seen = {k: v for k, v in self.protocols.items() if k in CLEARTEXT_RISK}
        # OPC UA servers advertising an unencrypted channel or anonymous logon, and clients seen using either
        self.opcua_weak = []
        for a in self.physical:
            fps = {(f.get("field"), f.get("value")) for f in (a.get("fingerprints") or [])}
            issues = []
            if any(k == "opcua_security_policies" and "None" in (v or "").split(", ") for k, v in fps):
                issues.append("SecurityPolicy None offered")
            if any(k == "opcua_security_modes" and "None" in (v or "").split(", ") for k, v in fps):
                issues.append("MessageSecurityMode None offered")
            if any(k == "opcua_user_tokens" and "Anonymous" in (v or "") for k, v in fps):
                issues.append("anonymous logon accepted")
            if any(k == "opcua_auth" and v == "Anonymous" for k, v in fps):
                issues.append("client authenticated anonymously")
            if any(k == "opcua_security_policy" and v == "None" for k, v in fps):
                issues.append("channel opened with SecurityPolicy None")
            if issues:
                self.opcua_weak.append((a, sorted(set(issues))))
        self.undocumented = [a for a in self.physical if not any(a.get(k) for k in ("location", "criticality", "purdue_level", "zone", "process_function", "owner"))]
        self.overrides = [a for a in self.assets if a.get("manual_type")]
        self.external = [r for r in self.relationships if r.get("category") == "Asset-to-external/unknown"]
        self.local_pairs = [r for r in self.relationships if r.get("category") == "Local asset-to-asset"]
        self.type_counts: dict[str, int] = {}
        for a in self.physical:
            self.type_counts[a.get("display_type") or "Unclassified"] = self.type_counts.get(a.get("display_type") or "Unclassified", 0) + 1
        self.reduction = (1 - len(self.relationships) / len(self.flows)) * 100 if self.flows and self.relationships else 0.0
        self.subnets: dict[str, list[dict]] = {}
        for asset in self.physical:
            for ip in (asset.get("ips") or "").split(","):
                if "." in ip and ip.count(".") == 3:
                    self.subnets.setdefault(".".join(ip.split(".")[:3]) + ".0/24", []).append(asset)
        dominant = max(self.subnets, key=lambda k: len(self.subnets[k])) if self.subnets else ""
        self.minority_subnets = {k: v for k, v in self.subnets.items() if k != dominant} if len(self.subnets) > 1 else {}
        self.zones = data.get("zones") or {}
        self.documented = [a for a in self.physical if (a.get("source") or "Passive capture") != "Passive capture"]
        self.documented_only = [a for a in self.physical if a.get("classification") == "Documented, not observed"]
        self.eol = [a for a in self.physical if (a.get("support_status") or "").startswith("End")]
        self.no_backup = [a for a in self.physical if a.get("backup_status") in ("No backup", "Unknown") or ((a.get("criticality") in ("High", "Critical")) and not a.get("backup_status"))]
        self.lifecycle_rows = [a for a in self.physical if any(a.get(k) for k in ("install_date", "end_of_life", "end_of_support", "support_status", "patch_status", "backup_status", "last_backup"))]
        self.crossing_rels = [r for r in self.relationships if r.get("crossing")]
        self.unexpected_rels = [r for r in self.relationships if r.get("decision") == "Unexpected"]
        self.unreviewed_crossings = [r for r in self.crossing_rels if r.get("decision", "Unknown") == "Unknown"]
        self.bypass_rels = [r for r in self.relationships if "bypass" in (r.get("crossing") or "")]
        self.drafts = self._findings()
        self.register = data.get("findings") or []
        self.findings = self.register if self.register else self.drafts
        self.register_mode = bool(self.register)
        for f in self.findings:
            f.setdefault("ref", f.get("id", ""))
            f.setdefault("kind", "Evidence gap"); f.setdefault("status", "Draft"); f.setdefault("horizon", "")
        self.unvalidated = [f for f in self.findings if f.get("status", "Draft") == "Draft"]
        self.rejected = [f for f in self.findings if f.get("status") == "Rejected"]
        self.reportable = [f for f in self.findings if f.get("status") != "Rejected"]

    def mac(self, value: str) -> str:
        return sanitize_mac(value) if self.sanitize else (value or "").upper()

    def label(self, asset: dict) -> str:
        return asset.get("name") or asset.get("display_type") or asset.get("manufacturer") or self.mac(asset.get("mac", ""))

    def coverage_words(self) -> tuple[str, str, str, str]:
        """(headline, body, fill, accent) for the coverage conclusion callout."""
        level = self.coverage.get("level")
        if level == "likely-mirror":
            return ("Mirror/TAP visibility likely", f"{fmt_int(self.third_party)} third-party unicast frames were observed, which is consistent with a configured SPAN/TAP or an otherwise privileged feed. Coverage of this network leg is plausible but must still be reconciled against switch configuration and drawings before it is treated as complete.", GREEN_BG, GREEN)
        if level == "mixed":
            pts = self.coverage.get("points") or []
            good = [p["point"] for p in pts if p.get("level") == "likely-mirror"]
            weak = [p["point"] for p in pts if p.get("level") in ("limited", "none")]
            return ("Adequate at mirrored collection points; limited elsewhere",
                    f"Third-party unicast traffic ({fmt_int(self.third_party)} frames) was observed at {', '.join(good)}, consistent with a configured SPAN/TAP: inventory and communications for those legs are plausible pending reconciliation. Collection at {', '.join(weak)} saw only broadcast and collector-directed traffic (access-port visibility) and does not establish the inventory for that leg.", AMBER_BG, AMBER)
        if level == "unknown":
            return ("Coverage depends on the original capture", "Evidence was imported from a PCAP whose capture point was not observed by the assessor. Visibility claims must come from the party that performed the capture.", AMBER_BG, AMBER)
        if level == "none":
            return ("No evidence collected", self.coverage.get("message", ""), RED_BG, RED)
        return ("Inadequate for inventory completeness", f"The collector observed the local host, gateway traffic, broadcast/multicast frames and adjacent identities from {', '.join(self.points) or 'the collection point'}. It did not observe conversations occurring only between other endpoints ({fmt_int(self.third_party)} third-party unicast frames). The inventory below is a lower bound, not a complete list.", RED_BG, RED)

    def evidence_status(self, keys: tuple[str, ...]) -> tuple[str, str]:
        """Summarise checklist status across sites for the evidence-sources table."""
        entries = [entry for key in keys for entry in self.checklist_status.get(key, [])]
        if not entries:
            return "Not recorded in tool", "Unknown"
        complete = [site for site, item in entries if item["status"] == "Complete"]
        partial = [site for site, item in entries if item["status"] == "In progress"]
        na = [site for site, item in entries if item["status"] == "Not applicable"]
        parts = []
        if complete: parts.append(f"Complete: {', '.join(complete)}")
        if partial: parts.append(f"In progress: {', '.join(partial)}")
        if na: parts.append(f"N/A: {', '.join(na)}")
        missing = [site for site, item in entries if item["status"] == "Not started"]
        if missing: parts.append(f"Not started: {', '.join(missing)}")
        confidence = "Assessor-verified" if complete and not missing and not partial else "Partial" if complete or partial else "Unknown"
        return "; ".join(parts), confidence

    def _findings(self) -> list[dict]:
        out: list[dict] = []
        level = self.coverage.get("level")
        if level in ("limited", "none") or (level != "mixed" and "Unconfirmed access port" in self.access_methods):
            out.append({"id": "OBS-01", "title": "Passive visibility is inadequate for inventory completeness", "rating": "High priority", "confidence": "High", "owner": "OT network / site operations",
                        "condition": f"No meaningful third-party unicast traffic was observed ({fmt_int(self.third_party)} frames across {len(self.sessions)} session(s)). Access method recorded: {', '.join(self.access_methods) or 'not recorded'}.",
                        "evidence": f"{fmt_int(self.third_party)} third-party unicast packets; {fmt_int(self.local_unicast)} local unicast; {fmt_int(self.broadcast)} broadcast/multicast; capture duration {fmt_duration_words(self.total_duration)}; no switch configuration or drawing evidence recorded in the tool.",
                        "impact": "Unknown endpoints, communications and dependencies could be omitted from the assessment, creating false assurance if the limitation is not disclosed.",
                        "recommendation": "Develop a collection-point matrix by network leg and obtain approved SPAN/TAP, customer PCAP, switch, firewall, NetFlow, drawing and walkdown evidence as available.",
                        "closure": "Every in-scope network leg has an identified evidence source, a documented time window and a reconciled expected-versus-observed inventory."})
        if self.legs_no_evidence:
            names = ", ".join(f"{l['site']}: {l['name']} ({l.get('status')}, {l.get('evidence_source')})" for l in self.legs_no_evidence[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Network legs without an evidence source", "rating": "High priority", "confidence": "High", "owner": "Assessment lead / site operations",
                        "condition": f"{len(self.legs_no_evidence)} of {len(self.legs)} recorded network leg(s) have no collected evidence: {names}.",
                        "evidence": "Collection-point matrix maintained in the tool; legs marked Planned, Not accessible or with evidence source 'None yet'.",
                        "impact": "Assets and communications on these legs are absent from the inventory and communication map. Any segmentation conclusion about them is unsupported.",
                        "recommendation": "Obtain an evidence source for each leg (SPAN/TAP, customer PCAP, NetFlow, switch tables or, at minimum, drawings plus interview) or formally record the leg as out of scope with the reason.",
                        "closure": "Every leg has status Collected, Partial with documented limitation, or Out of scope with a recorded reason."})
        if self.undocumented:
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Asset identity and context require drawing and walkdown reconciliation", "rating": "Moderate", "confidence": "High", "owner": "OT engineering / asset owner",
                        "condition": f"{len(self.physical)} likely physical asset(s) and {len(self.derived)} derived identit(ies) were inferred from passive evidence. {len(self.undocumented)} physical asset(s) have no location, criticality, Purdue level, zone, function or owner recorded.",
                        "evidence": f"Assessment context fields empty for: {', '.join(self.label(a) for a in self.undocumented[:8])}{' and others' if len(self.undocumented) > 8 else ''}. {len(self.overrides)} assessor override(s) recorded.",
                        "impact": "Findings cannot be prioritized by operational consequence until each asset's process function, criticality and zone are known.",
                        "recommendation": "Reconcile passive evidence with drawings, equipment lists, controller projects, switch tables, backups, interviews and physical labels. Preserve conflicts as open evidence issues rather than overwriting source claims.",
                        "closure": "Every physical asset carries a validated type, location, function, owner, criticality and zone, or an explicit open-issue record."})
        if self.external:
            top = sorted(self.external, key=lambda r: -int(r.get("packets") or 0))[:5]
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "External communication pathways require policy validation", "rating": "Moderate", "confidence": "Moderate", "owner": "OT security / firewall owner",
                        "condition": f"{len(self.external)} relationship(s) between a local asset and an external or unmapped endpoint were observed.",
                        "evidence": "; ".join(f"{r['endpoint_a']} ↔ {r['endpoint_b']} ({r.get('protocols')}, {fmt_int(r.get('packets'))} pkts)" for r in top),
                        "impact": "Outbound or inbound pathways that are not covered by an approved conduit definition are a common segmentation weakness and a vendor-access blind spot.",
                        "recommendation": "Compare each external relationship with the firewall rule base, approved conduit list and vendor remote-access records. Classify each as approved, tolerated or unexpected.",
                        "closure": "Every external relationship is mapped to an approved conduit or has a remediation owner and date."})
        if self.minority_subnets:
            detail = "; ".join(f"{net}: {', '.join(self.label(a) for a in assets[:5])}" for net, assets in self.minority_subnets.items())
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Multiple IPv4 subnets observed on the same Layer-2 segment", "rating": "Moderate", "confidence": "High", "owner": "OT network owner",
                        "condition": f"Assets from {len(self.subnets)} IPv4 subnets share a broadcast domain. Minority subnet(s): {detail}.",
                        "evidence": "IP evidence (ARP, DHCP, frame source) per Layer-2 identity from the collection point(s) used.",
                        "impact": "A device on an unexpected subnet within an OT segment can indicate a misconfiguration, a guest/overlay network bridged into the segment, a vendor device with factory addressing, or an undocumented path between zones.",
                        "recommendation": "Identify each minority-subnet device, confirm whether its addressing is intentional and documented, and verify no routing or bridging exists between the subnets that bypasses the zone boundary.",
                        "closure": "Each subnet on the segment is documented with purpose and owner, or the stray device is corrected."})
        if self.unexpected_rels:
            detail = "; ".join(f"{r['endpoint_a']} ↔ {r['endpoint_b']} ({r.get('protocols')}; {r.get('crossing') or 'within level'})" for r in self.unexpected_rels[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Communications marked unexpected against the conduit baseline", "rating": "High priority", "confidence": "High", "owner": "OT security / firewall owner",
                        "condition": f"{len(self.unexpected_rels)} observed relationship(s) were reviewed by the assessor and marked Unexpected: {detail}.",
                        "evidence": "Passive flow evidence plus assessor conduit decisions recorded in the tool.",
                        "impact": "Unexpected pathways are undocumented attack and failure paths; they typically indicate a missing firewall rule, a bridged network, a vendor connection or a misconfigured host.",
                        "recommendation": "Trace each unexpected relationship to its physical and logical path, decide whether it is required, and either document it as an approved conduit with a control or remove it under change control.",
                        "closure": "No relationship in the register remains marked Unexpected without an owner and remediation date."})
        if self.bypass_rels and not self.unexpected_rels:
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Direct OT-to-enterprise communications bypass the industrial DMZ", "rating": "High priority", "confidence": "Moderate", "owner": "OT network owner",
                        "condition": f"{len(self.bypass_rels)} relationship(s) connect assets at Purdue Level 3 or below directly to Level 4/5 assets with no industrial DMZ in between.",
                        "evidence": "; ".join(f"{r['endpoint_a']} ({r['level_a']}) ↔ {r['endpoint_b']} ({r['level_b']}): {r.get('protocols')}" for r in self.bypass_rels[:6]),
                        "impact": "Any compromise of an enterprise host has a direct path to control-system assets; ISA/IEC 62443 and NIST SP 800-82 both expect these flows to terminate in a DMZ.",
                        "recommendation": "Confirm the level assignments, then design DMZ-terminated replacements (historian replica, jump host, file transfer broker) for each flow.",
                        "closure": "No Level ≤3 to Level ≥5 relationship remains, or each is documented as approved with compensating controls."})
        if self.unreviewed_crossings and self.zones.get("assigned"):
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Boundary-crossing communications not yet reviewed against a conduit baseline", "rating": "Moderate", "confidence": "High", "owner": "Assessment team / OT engineering",
                        "condition": f"{len(self.unreviewed_crossings)} of {len(self.crossing_rels)} relationship(s) that cross a Purdue level or reach an external endpoint have no conduit decision.",
                        "evidence": "Conduit decisions recorded in the tool; relationships with decision Unknown.",
                        "impact": "The segmentation assessment cannot conclude which crossings are approved until each is classified.",
                        "recommendation": "Review each crossing with the network and OT owners against firewall rules and drawings; mark Approved, Tolerated or Unexpected with the business purpose.",
                        "closure": "Every crossing relationship carries a decision and purpose."})
        if self.zones.get("physical") and self.zones.get("assigned", 0) < self.zones.get("physical", 0) - self.zones.get("infrastructure", 0):
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Purdue level not assigned for all physical assets", "rating": "Low", "confidence": "High", "owner": "Assessment team",
                        "condition": f"{self.zones['assigned']} of {self.zones['physical'] - self.zones.get('infrastructure', 0)} non-infrastructure physical assets have a Purdue level; zone-crossing analysis is incomplete for the rest.",
                        "evidence": "Asset assessment context in the tool.",
                        "impact": "Relationships involving unassigned assets cannot be classified as within-zone or boundary-crossing.",
                        "recommendation": "Assign a level to each physical asset from drawings, function and walkdown evidence.",
                        "closure": "All physical assets carry a Purdue level or are explicitly recorded as out of scope."})
        if self.eol:
            eol_list = ", ".join("%s (%s; %s)" % (self.label(a), a.get("model") or a.get("manufacturer") or "model unknown", a.get("support_status")) for a in self.eol[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "End-of-life or end-of-support OT assets in service", "rating": "High priority" if any(a.get("criticality") in ("High", "Critical") for a in self.eol) else "Moderate", "confidence": "High", "owner": "OT engineering / asset owner",
                        "condition": f"{len(self.eol)} asset(s) are recorded as end of life or end of support: {eol_list}{' and others' if len(self.eol) > 8 else ''}.",
                        "evidence": "Lifecycle fields recorded from walkdown, drawings or customer inventory; vendor lifecycle notices should be attached to the evidence register.",
                        "impact": "No vendor security fixes; replacement parts and engineering support become scarce; failure or compromise recovery depends on spares and backups.",
                        "recommendation": "Confirm lifecycle status with the vendor, add each unit to the replacement roadmap with a date, and apply compensating controls (segmentation, restricted access, monitored conduits, verified backups) until replaced.",
                        "closure": "Each EOL/EOS asset has a funded replacement date or a documented risk acceptance with compensating controls."})
        if self.no_backup:
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Controller and application backups missing or unverified", "rating": "Moderate", "confidence": "Moderate", "owner": "OT engineering",
                        "condition": f"{len(self.no_backup)} asset(s) have no backup, an unknown backup status, or are rated High/Critical with no backup status recorded: {', '.join(self.label(a) for a in self.no_backup[:8])}{' and others' if len(self.no_backup) > 8 else ''}.",
                        "evidence": "Backup status fields recorded per asset; restore tests not evidenced.",
                        "impact": "Recovery from failure, ransomware or a bad change depends on rebuilding logic and configuration from memory or vendor archives.",
                        "recommendation": "Establish a controller/HMI/historian backup schedule with offline copies and periodic restore tests; record last backup and last successful restore per asset.",
                        "closure": "Every critical asset has a current backup and a documented restore test."})
        if self.cleartext_seen:
            names = ", ".join(f"{IT_SERVICE_PROTOCOLS.get(k, k)} ({fmt_int(v['flows'])} flows)" for k, v in sorted(self.cleartext_seen.items()))
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Cleartext management or file-transfer protocols observed", "rating": "Moderate", "confidence": "Moderate", "owner": "OT engineering / network owner",
                        "condition": f"Protocols that commonly carry credentials or configuration in cleartext were observed: {names}.",
                        "evidence": "Port-based protocol identification from passive flows; payloads were not inspected for credentials.",
                        "impact": "Credentials and device configuration can be captured by anyone with the same network visibility this assessment had.",
                        "recommendation": "Confirm which devices require these services, disable unused services and prefer SSH, HTTPS, SNMPv3 or vendor-secured equivalents where supported.",
                        "closure": "Each cleartext service is either documented as operationally required with compensating controls or disabled."})
        if self.opcua_weak:
            detail = "; ".join(f"{self.label(a)}: {', '.join(issues)}" for a, issues in self.opcua_weak[:8])
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "OPC UA endpoints allow unencrypted or anonymous sessions", "rating": "Moderate", "confidence": "High", "owner": "OT engineering / SCADA owner",
                        "condition": f"{len(self.opcua_weak)} OPC UA endpoint(s) advertise or use a security policy of None and/or anonymous logon: {detail}.",
                        "evidence": "Decoded from OPC UA GetEndpoints/CreateSession/OpenSecureChannel/ActivateSession messages observed passively; the server's own endpoint list is the source for what it offers.",
                        "impact": "With SecurityPolicy None the session is readable and forgeable by anyone with the network position this assessment had; anonymous logon means any such host can browse and, depending on node permissions, write process values.",
                        "recommendation": "Disable the None policy and anonymous token on each server (keep Basic256Sha256 or Aes128_Sha256_RsaOaep with Sign&Encrypt), issue application certificates through a managed trust list, and give collectors and historians named accounts with read-only node permissions.",
                        "closure": "GetEndpoints on each server lists no None policy and no anonymous token; existing clients reconnect with certificates and named users."})
        if self.ot_seen:
            names = ", ".join(f"{OT_PROTOCOLS[k]} ({fmt_int(v['flows'])} flows)" for k, v in sorted(self.ot_seen.items()))
            out.append({"id": f"OBS-{len(out) + 1:02d}", "title": "Industrial protocols observed; conduit approval baseline not yet established", "rating": "Informational", "confidence": "High", "owner": "OT engineering",
                        "condition": f"Industrial control protocols were observed: {names}.",
                        "evidence": "Protocol identification by well-known port and, where present, decoded device-identification payloads.",
                        "impact": "Industrial protocols generally carry no authentication; any host that can reach the controller can typically read or write process values.",
                        "recommendation": "Document each industrial relationship as an approved conduit with its zone pair, direction and purpose; restrict reachability to the documented peers.",
                        "closure": "An approved conduit baseline exists and observed industrial relationships reconcile to it."})
        out.append({"id": "POS-01", "title": "Raw evidence is retained separately from normalized relationships and inferences", "rating": "Positive", "confidence": "High", "owner": "Assessment team",
                    "condition": f"{fmt_int(len(self.flows))} raw flow records, {fmt_int(len(self.relationships))} deduplicated relationships, {fmt_int(len(self.discovery))} discovery-traffic groups and every fingerprint claim are preserved with confidence and evidence.",
                    "evidence": "Assessment export and CSV registers generated by the collector.",
                    "impact": "Conclusions are auditable and can be re-examined without re-collecting.",
                    "recommendation": "Keep the export with the evidence register; do not edit exported evidence files by hand.",
                    "closure": "Not applicable."})
        for f in out:
            f.update(refs_for(f["title"]))
        return out


# ----------------------------------------------------------------------------- report body
def build_report(data: dict, meta: dict | None = None) -> bytes:
    meta = meta or {}
    a = Analysis(data, bool(meta.get("sanitize")))
    d = Doc()
    title = meta.get("title") or "OT / ICS Cybersecurity and Site Assessment"
    prepared_for = meta.get("prepared_for") or "Client name"
    prepared_by = meta.get("prepared_by") or "Assessor"
    banner = meta.get("banner") or "DRAFT — FOR ASSESSOR REVIEW"
    assessment = ", ".join(a.assessment_names) or "Unnamed assessment"
    today = datetime.now().strftime("%B %d, %Y")
    generated = data.get("generated_at", "")

    # Cover -----------------------------------------------------------------
    d.runs(d.run(banner, bold=True, size=9, color=RED, caps=True), before=0, after=480)
    d.para(title, "Title")
    d.para("Passive discovery, architecture validation and risk-focused recommendations", "Subtitle")
    d.labeled("Prepared for", prepared_for)
    d.labeled("Prepared by", prepared_by)
    d.labeled("Assessment", f"{assessment} — {', '.join(a.sites) or 'site not recorded'}")
    d.labeled("Evidence", f"OT Scout passive collection, {len(a.sessions)} session(s), export generated {generated}")
    d.labeled("Report date", today)
    d.para("", after=240)
    d.callout("Important", "This document was generated by OT Scout from passive network evidence. Automatically generated observations are drafts for assessor validation: every finding, rating and owner must be reviewed, reworded or removed before the report is delivered to a client. Nothing in this report asserts a deficiency solely because a port, protocol or destination was observed.")

    # Document control --------------------------------------------------------
    d.h1("Document control")
    d.h2("Revision history")
    d.table(["Version", "Date", "Author", "Description"], [["0.1", today, prepared_by, "Generated from OT Scout evidence; pending assessor review"]], [0.12, 0.18, 0.25, 0.45])
    d.h2("Reference documentation")
    d.table(["Reference", "Use in this report"], [
        ["NIST SP 800-82 Rev. 3, Guide to Operational Technology Security", "Passive discovery limitations, OT-safe assessment practice, control families"],
        ["ISA/IEC 62443", "Zones, conduits, security levels and industrial risk terminology"],
        ["Purdue Enterprise Reference Architecture", "Functional levels used to communicate boundaries"],
        ["NIST Cybersecurity Framework; CIS Controls", "Mapping of recommendations to recognised control families"],
        ["Client policies, site standards and safety procedures", "Authorisation, access and operational constraints"],
    ], [0.45, 0.55])
    d.h2("Disclaimer")
    d.para("Assessment conclusions are bounded by the collection points, time windows and evidence sources recorded in this report. Missing observations are treated as unknown — not as proof that a device, pathway or control does not exist. Manufacturer, model, firmware, serial and device type may be inferred from partial evidence and require confirmation. No production change should be implemented without operational review, approved change control, testing and rollback planning.")
    d.h2("Scope")
    d.h3("Data collection")
    d.bullet(f"Passive Ethernet capture at: {', '.join(a.points) or 'no collection point recorded'}.")
    d.bullet(f"Access method(s): {', '.join(a.access_methods) or 'not recorded'}.")
    d.bullet(f"Total observation window: {fmt_duration_words(a.total_duration)} across {len(a.live_sessions)} live session(s){'; plus ' + str(len(a.sessions) - len(a.live_sessions)) + ' imported PCAP session(s)' if len(a.sessions) != len(a.live_sessions) else ''}.")
    d.bullet("No probes, scans, SNMP queries or protocol interrogation were transmitted by the collector.")
    d.h3("Assessment analysis")
    d.bullet("Layer-2 identity correlation, IEEE OUI manufacturer lookup and passive protocol fingerprinting.")
    d.bullet("Separation of likely physical assets from derived or virtual identities.")
    d.bullet("Normalisation of directional flows into deduplicated endpoint relationships, categorised as local, external or unmapped.")
    d.bullet("Separation of broadcast, multicast and service-discovery traffic from unicast relationships.")
    d.h3("Out of scope")
    d.bullet("Active scanning, configuration retrieval, vulnerability testing or any traffic generation toward OT equipment.")
    d.bullet("Endpoints, VLANs and network legs not visible from the recorded collection points.")
    d.bullet("Encrypted payload inspection and TCP stream reassembly.")

    # Executive readout -------------------------------------------------------
    d.h1("Executive readout")
    d.para(f"The passive collector converted {fmt_int(a.packets)} observed frames into a defensible evidence set: {len(a.assets)} Layer-2 identities, of which {len(a.physical)} are supported as likely physical assets, {fmt_int(len(a.relationships))} deduplicated unicast relationships and {fmt_int(len(a.discovery))} broadcast/service-discovery groups. Each automated conclusion carries its evidence and confidence rather than presenting every observed MAC or IP address as a confirmed asset.")
    d.tiles([(fmt_int(len(a.physical)), "Likely physical assets"), (fmt_int(len(a.assets)), "L2 identities"), (fmt_int(len(a.relationships)), "Relationships"), (fmt_int(a.packets), "Packets")])
    d.h2("What leadership should know")
    head, body, fill, accent = a.coverage_words()
    if a.coverage.get("level") == "likely-mirror":
        d.bullet(f"Collection observed third-party traffic ({fmt_int(a.third_party)} frames), so the inventory for the monitored leg is plausible but still requires reconciliation.")
    elif a.coverage.get("level") == "mixed":
        pts = a.coverage.get("points") or []
        d.bullet(f"Mirrored collection at {', '.join(p['point'] for p in pts if p.get('level') == 'likely-mirror')} gave credible visibility ({fmt_int(a.third_party)} third-party frames); collection at {', '.join(p['point'] for p in pts if p.get('level') in ('limited', 'none'))} was access-port only and does not establish that leg's inventory.")
    else:
        d.bullet("Collection worked, but the feed exposed no meaningful third-party unicast traffic; the observed inventory is incomplete by design.")
    if a.documented:
        d.bullet(f"{len(a.physical)} physical assets in the inventory: {len(a.physical) - len(a.documented_only)} observed on the network ({len(a.documented) - len(a.documented_only)} of them also confirmed by walkdown or documentation) and {len(a.documented_only)} added from walkdown, drawings or interviews because they do not transmit on a monitored segment; {len(a.derived)} identit(ies) were retained as derived or virtual evidence rather than inflated into separate assets.")
    else:
        d.bullet(f"{len(a.physical)} physical device(s) were supported by passive evidence; {len(a.derived)} additional identit(ies) were retained as derived or virtual evidence rather than inflated into separate assets.")
    if a.ot_seen:
        d.bullet(f"Industrial protocols observed: {', '.join(OT_PROTOCOLS[k] for k in sorted(a.ot_seen))}. A conduit approval baseline is needed before these can be judged.")
    else:
        d.bullet("No industrial control protocols (Modbus, DNP3, EtherNet/IP, S7, OPC UA, BACnet, MQTT) were observed from the collection points used.")
    if a.external:
        d.bullet(f"{len(a.external)} relationship(s) reach external or unmapped endpoints and require validation against firewall policy and vendor-access records.")
    d.bullet("A production assessment must reconcile passive evidence with drawings, switch and firewall data, interviews, configuration reviews and physical walkdowns.")
    d.h2("Findings summary" if a.register_mode else "Observation summary")
    d.table(["Ref", "Finding / observation", "Type", "Rating", "Status", "Recommended owner"],
            [[f["ref"], f["title"], f.get("kind", ""), (f["rating"], RED if f["rating"] in ("Critical", "High priority") else GREEN if f["rating"] == "Positive" else AMBER if f["rating"] == "Moderate" else MUTED, True), f.get("status", "Draft"), f["owner"]] for f in a.reportable],
            [0.08, 0.38, 0.16, 0.12, 0.10, 0.16])

    # 1 Scope, objectives, evidence -------------------------------------------
    d.h1("1. Scope, objectives and evidence")
    d.para("This section establishes what was observed, what remains unknown, why the condition matters operationally and what action should be taken without increasing risk to live operations.")
    d.h2("Assessment objectives")
    for line in ["Establish an evidence-backed OT asset and endpoint inventory.",
                 "Map OT-to-OT, OT-to-IT, telemetry, historian and remote-access communications.",
                 "Assess Purdue levels, ISA/IEC 62443 zones and conduits, segmentation boundaries and firewall pathways.",
                 "Evaluate monitoring, logging, configuration management, backup and recovery, vendor access and operational resilience.",
                 "Produce prioritised findings with operational impact, dependencies, accountable ownership and a staged remediation roadmap."]:
        d.bullet(line)
    d.h2("Evidence sources and current status")
    ev_rows = [["Passive packet evidence", "Assets, protocols, relationships, timing", f"Collected — {fmt_duration_words(a.total_duration)}, {len(a.sessions)} session(s)", "High for observed traffic"]]
    for label, purpose, keys in (("Network drawings and documentation", "Expected topology, zones, remote sites", ("documentation",)),
                                 ("Switch / firewall / log review", "Ports, VLANs, routes, rules, boundaries, logging", ("config_review",)),
                                 ("SCADA / historian review", "Roles, dependencies, access paths", ("scada_historian",)),
                                 ("Remote access and telemetry paths", "Vendor access, jump hosts, radio/cellular backhaul", ("remote_access", "telemetry")),
                                 ("Interviews", "Operating practice, dependencies, constraints", ("interviews",)),
                                 ("Physical walkdown", "Physical location, function, safety context", ("walkdown",))):
        status, conf = a.evidence_status(keys)
        ev_rows.append([label, purpose, status, conf])
    ev_rows.append(["Asset context entered", "Location, criticality, zone, function, owner per asset", f"{len(a.physical) - len(a.undocumented)} of {len(a.physical)} physical assets", "Assessor-entered"])
    d.table(["Evidence source", "Purpose", "Status", "Confidence"], ev_rows, [0.24, 0.28, 0.32, 0.16])
    if a.site_records:
        d.h2("Site validation")
        for site in a.site_records:
            d.h3(f"{site.get('name', '')}{' — ' + site['facility_type'] if site.get('facility_type') else ''}")
            if site.get("operational_function"): d.labeled("Operational function", site["operational_function"])
            if site.get("walkdown_date"): d.labeled("Walkdown date", site["walkdown_date"])
            if site.get("contacts"): d.labeled("Contacts", site["contacts"])
            if site.get("documentation"): d.labeled("Documentation obtained", site["documentation"])
            if site.get("deviations"): d.labeled("Deviations from expected architecture", site["deviations"])
            d.table(["Checklist item", "Status", "Evidence reference", "Notes"],
                    [[c["label"], (c["status"], GREEN if c["status"] == "Complete" else AMBER if c["status"] == "In progress" else MUTED if c["status"] == "Not applicable" else RED, True), c.get("evidence", ""), c.get("notes", "")] for c in site.get("checklist") or []],
                    [0.34, 0.14, 0.26, 0.26], size=8)
            d.muted(f"{site.get('checklist_complete', 0)} of {site.get('checklist_total', 0)} items complete or not applicable.")
    else:
        d.callout("No site validation recorded", "No site checklist or collection-point matrix has been entered in the tool. Coverage below is derived from capture sessions alone.")
    d.h2("Safety and collection constraints")
    d.callout("Non-intrusive default", "Passive discovery does not transmit probes. Any active SNMP or protocol interrogation would require written authorisation, defined targets, rate limits, change control, operational approval and rollback procedures.", BLUE_BG, BLUE)

    # 2 Coverage ----------------------------------------------------------------
    d.h1("2. Collection coverage and confidence")
    d.para("Coverage is reported separately from findings. This prevents a short or poorly positioned capture from creating false assurance.")
    d.tiles([(fmt_duration_words(a.total_duration), "Capture duration"), (fmt_int(a.third_party), "Third-party unicast"), (fmt_int(a.broadcast), "Broadcast / multicast"), (fmt_int(a.local_unicast), "Local unicast")])
    d.h2("Coverage conclusion")
    d.callout(head, body, fill, accent)
    d.h2("Evidence interpretation")
    d.table(["Evidence", "Observed result", "Assessment meaning"], [
        ["Collection method", ", ".join(a.access_methods) or "Not recorded", "No basis to claim full segment visibility" if "Unconfirmed access port" in a.access_methods or not a.access_methods else "Configured feed; validate the mirror/TAP scope against switch configuration"],
        ["Third-party unicast", f"{fmt_int(a.third_party)} packets", "Feed does not resemble a configured SPAN/TAP source" if a.third_party < 10 else "Consistent with mirror/TAP visibility at the mirrored collection point(s)"],
        ["Drawings / switch data", "Not recorded in tool", "Expected-versus-observed reconciliation cannot be completed"],
        ["Capture duration", fmt_duration_words(a.total_duration), "Functional test only; silent or periodic devices may be absent" if a.total_duration < 4 * 3600 else "Extended window; daily or shift-based periodic traffic may still be absent"],
    ], [0.22, 0.30, 0.48])
    d.h2("Collection sessions")
    d.table(["#", "Collection point", "Access / source", "Interface / file", "Started (UTC)", "Duration", "Packets", "3rd-party"], [
        [str(s.get("id", "")), s.get("collection_point", ""), f"{s.get('access_method', '')} / {s.get('source_type', '')}", s.get("interface", ""), (s.get("started_at") or "").replace("+00:00", ""), fmt_duration_words(s.get("duration_seconds")), fmt_int(s.get("packets")), fmt_int(s.get("third_party_unicast"))]
        for s in a.sessions], [0.04, 0.18, 0.20, 0.14, 0.16, 0.10, 0.09, 0.09], size=8)
    if a.legs:
        d.h2("Coverage by network leg")
        d.table(["Site / network leg", "Purdue", "Evidence source", "Status", "Collected evidence", "Limitations"],
                [[[l["name"], l["site"]], l.get("purdue_level", ""), l.get("evidence_source", ""),
                  (l.get("status", ""), GREEN if l.get("status") == "Collected" else AMBER if l.get("status") == "Partial" else RED if l.get("status") in ("Planned", "Not accessible") else MUTED, True),
                  (f"{l['coverage']['sessions']} session(s), {l['coverage'].get('duration', '')}, {fmt_int(l['coverage']['packets'])} pkts, {l['coverage']['assets_seen']} assets; {l['coverage']['signal']}" if l.get("coverage", {}).get("sessions") else l.get("coverage", {}).get("signal", "")),
                  "; ".join(v for v in (l.get("time_window"), l.get("exclusions"), l.get("limitations")) if v)] for l in a.legs],
                [0.20, 0.08, 0.16, 0.10, 0.26, 0.20], size=8)
        d.muted(f"{len(a.legs) - len(a.legs_no_evidence)} of {len(a.legs)} legs have collected evidence. Collected evidence is computed from capture sessions whose collection point matches the leg.")
    d.h2("Required production collection plan")
    for line in ["Identify each network leg and the evidence source available for that leg.",
                 "Use configured SPAN/TAP feeds where approved; otherwise collect customer PCAP, NetFlow, firewall, ARP and switch-table evidence.",
                 "Reconcile observed endpoints against drawings, controller projects, historian tags, backups, maintenance records and the physical walkdown.",
                 "Record every collection point, time window, access method, exclusion and visibility limitation in the evidence register."]:
        d.bullet(line)

    # 3 Inventory -----------------------------------------------------------------
    d.h1("3. Asset inventory and passive fingerprints")
    d.para("OT Scout anchors the inventory on Layer-2 identity and retains names, IP addresses, manufacturer, protocol fingerprints, collection points and assessor overrides as separate evidence claims. Packet volume alone does not convert a derived MAC into a physical asset.")
    if a.documented:
        d.callout("Evidence sources", f"{len(a.physical) - len(a.documented)} asset(s) from passive capture only; {len(a.documented) - len(a.documented_only)} corroborated by both passive evidence and a documented record; {len(a.documented_only)} documented only (walkdown, drawings, interview or customer inventory) and not observed on the network.", BLUE_BG, BLUE)
    d.h2("Likely physical assets by type")
    type_rows = []
    for t, n in sorted(a.type_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        members = [v for v in a.physical if (v.get("display_type") or "Unclassified") == t]
        confs = [int(v.get("type_confidence") or 0) for v in members]
        overridden = sum(1 for v in members if v.get("manual_type"))
        d_rng = f"{min(confs)}–{max(confs)}%" if min(confs) != max(confs) else f"{confs[0]}%"
        type_rows.append([t, str(n), d_rng, f"{overridden} of {n} assessor-confirmed" if overridden else "Automatic inference only"])
    d.table(["Device type (displayed)", "Count", "Confidence", "Basis"], type_rows or [["None", "0", "—", "No physical assets inferred"]], [0.40, 0.10, 0.15, 0.35])
    d.h2("Asset inventory")
    rows = []
    for x in sorted(a.assets, key=lambda v: (not v.get("physical_asset"), -int(v.get("packets") or 0))):
        ctx = [v for v in (x.get("location"), x.get("criticality") and f"Criticality: {x['criticality']}", x.get("purdue_level"), x.get("zone") and f"Zone: {x['zone']}") if v]
        rows.append([[x.get("name") or "Unnamed", a.mac(x.get("mac", "")), (x.get("ips") or "").replace(",", ", ")],
                     [x.get("manufacturer") or "—", x.get("model") or ""],
                     [x.get("display_type") or "—", f"{x.get('type_source', '')} · {x.get('type_confidence', 0)}%"],
                     [x.get("classification") or "", x.get("classification_evidence") or ""],
                     ("Yes", GREEN, True) if x.get("physical_asset") else ("No", AMBER, True),
                     "; ".join(ctx) or ("Not documented", MUTED)])
    d.table(["Identity / MAC / IPs", "Manufacturer / model", "Likely type", "Classification", "Physical", "Assessment context"], rows or [["No assets observed", "", "", "", "", ""]], [0.24, 0.16, 0.16, 0.19, 0.09, 0.16], size=8)
    d.muted(f"Source: OT Scout assessment export generated {generated}. {'MAC addresses sanitised for distribution. ' if a.sanitize else ''}Physical count excludes locally administered, low-evidence identities that are likely virtual or derived.")
    fp_rows = []
    for x in a.assets:
        for f in x.get("fingerprints") or []:
            fp_rows.append([a.label(x), f.get("field", ""), f.get("value", ""), f.get("evidence", ""), f"{f.get('confidence', 0)}%", fmt_int(f.get("packets"))])
    if a.lifecycle_rows:
        d.h2("Lifecycle observations")
        d.table(["Asset", "Manufacturer / model", "Firmware", "Installed", "EOL / EOS", "Support status", "Patch status", "Backup"],
                [[a.label(x), f"{x.get('manufacturer') or ''} {x.get('model') or ''}".strip(), x.get("firmware") or "", x.get("install_date") or "", " / ".join(v for v in (x.get("end_of_life"), x.get("end_of_support")) if v),
                  (x.get("support_status") or "", RED if (x.get("support_status") or "").startswith("End") else AMBER if x.get("support_status") in ("Extended support", "Unknown") else GREEN, True),
                  x.get("patch_status") or "", (f"{x.get('backup_status') or ''}{' · ' + x['last_backup'] if x.get('last_backup') else ''}", RED if x.get("backup_status") in ("No backup",) else AMBER if x.get("backup_status") in ("Backed up, untested", "Unknown") else INK)] for x in a.lifecycle_rows],
                [0.16, 0.16, 0.08, 0.08, 0.13, 0.11, 0.14, 0.14], size=8)
        d.muted(f"{len(a.eol)} asset(s) at end of life/support; {len(a.no_backup)} with missing or unverified backups.")
    d.h2("Passive fingerprint claims")
    if fp_rows:
        d.table(["Asset", "Field", "Value", "Evidence", "Confidence", "Packets"], fp_rows[:60], [0.22, 0.14, 0.30, 0.14, 0.10, 0.10], size=8)
        if len(fp_rows) > 60:
            d.muted(f"{len(fp_rows) - 60} further fingerprint claims are in the assets export.")
    else:
        d.para("No protocol fingerprint payloads (DHCP, HTTP, LLDP, Modbus device identification, EtherNet/IP ListIdentity, BACnet I-Am) were observed.")
    d.h2("Fingerprint confidence model")
    examples = sorted(a.physical, key=lambda v: -int(v.get("type_confidence") or 0))
    hi = next((f"{v.get('display_type')} — {v.get('type_confidence')}%" for v in examples if int(v.get("type_confidence") or 0) >= 85), "None in this data set")
    mid = next((f"{v.get('display_type')} — {v.get('type_confidence')}%" for v in examples if 60 <= int(v.get("type_confidence") or 0) < 85), "None in this data set")
    lo = next((f"{v.get('display_type')} — {v.get('type_confidence')}%" for v in examples if int(v.get("type_confidence") or 0) < 60), "None in this data set")
    d.table(["Confidence band", "How it is used", "Example from this data"], [
        ["High (85–100%)", "Strong protocol or behavioural evidence; still subject to assessor validation", hi],
        ["Moderate (60–84%)", "Plausible type inferred from OUI, hostname or protocol context", mid],
        ["Low (<60%)", "Lead for follow-up; not a confirmed device identity", lo],
        ["Assessor override", "Manual conclusion retained alongside the original automatic inference", f"{len(a.overrides)} override(s) recorded" if a.overrides else "Not yet used"],
    ], [0.22, 0.48, 0.30])
    d.callout("Design principle", "The report distinguishes observation, automated inference and assessor judgement. Confidence does not replace validation.", BLUE_BG, BLUE)

    # 4 Communications ---------------------------------------------------------------
    d.h1("4. Communications and segmentation analysis")
    d.para(f"The collector normalised {fmt_int(len(a.flows))} directional flow records into {fmt_int(len(a.relationships))} endpoint relationships and {fmt_int(len(a.discovery))} broadcast/service-discovery groups. This makes protocol and dependency review manageable while retaining the raw evidence for audit and troubleshooting.")
    d.tiles([(fmt_int(len(a.flows)), "Raw flows"), (fmt_int(len(a.relationships)), "Deduplicated relationships"), (f"{a.reduction:.1f}%", "Relationship reduction"), (fmt_int(len(a.discovery)), "Discovery groups")])
    d.h2("Relationship categories")
    d.table(["Category", "Relationships", "Packets", "Assessment use"], [
        [c, fmt_int(v["count"]), fmt_int(v["packets"]), {"Local asset-to-asset": "Candidate zone-internal or conduit traffic; compare with expected architecture", "Asset-to-external/unknown": "External dependency — validate against firewall policy and vendor-access records", "Unmapped unicast": "Neither endpoint is a known local asset; identify the endpoints"}.get(c, "")]
        for c, v in sorted(a.categories.items())] or [["None", "0", "0", "No unicast relationships observed"]], [0.25, 0.13, 0.12, 0.50])
    if a.zones:
        d.h2("Purdue zone assignment and boundary crossings")
        d.tiles([(f"{a.zones.get('assigned', 0)}/{a.zones.get('physical', 0)}", "Assets with Purdue level"), (fmt_int(a.zones.get("assigned_from_suggestion", 0)), "Levels from tool suggestion"), (fmt_int(len(a.crossing_rels)), "Crossing relationships"),
                 (fmt_int(a.zones.get("decisions", {}).get("Approved", 0)), "Approved conduits"), (fmt_int(a.zones.get("unexpected", 0)), "Unexpected")])
        lv_rows = [[lv, fmt_int(v["assets"]), ", ".join(v["zones"]) or "—", ", ".join(v["names"][:8]) + (" …" if len(v["names"]) > 8 else "")] for lv, v in (a.zones.get("levels") or {}).items() if v["assets"] or lv != "Unassigned"]
        d.table(["Purdue level", "Assets", "ISA-62443 zones", "Assets (first 8)"], lv_rows or [["No levels assigned", "", "", ""]], [0.16, 0.08, 0.22, 0.54], size=8)
        d.muted(f"{a.zones.get('infrastructure', 0)} network infrastructure device(s) span levels and are not assigned. {a.zones.get('assigned_by_assessor', 0)} level(s) set by the assessor; {a.zones.get('assigned_from_suggestion', 0)} accepted from the tool's protocol-role suggestion and still subject to drawing validation; {a.zones.get('suggestions_pending', 0)} suggested but not accepted; {a.zones.get('no_suggestion', 0)} with no passive basis for a level.")
        pair_rows = [[f"{p['level_a']} ↔ {p['level_b']}", (p["crossing"] or "Within level", RED if "bypass" in (p["crossing"] or "") or "external" in (p["crossing"] or "") else AMBER if p["crossing"] else GREEN, True), fmt_int(p["relationships"]), p["protocols"],
                      f"A {p['decisions'].get('Approved', 0)} / T {p['decisions'].get('Tolerated', 0)} / U {p['decisions'].get('Unexpected', 0)} / ? {p['decisions'].get('Unknown', 0)}"] for p in a.zones.get("pairs") or []]
        d.table(["Zone pair", "Boundary", "Relationships", "Protocols", "Decisions (A/T/U/?)"], pair_rows or [["No unicast relationships", "", "", "", ""]], [0.22, 0.28, 0.10, 0.22, 0.18], size=8)
        d.muted("A = approved, T = tolerated, U = unexpected, ? = not yet reviewed. The Purdue diagram is exported separately from the tool as SVG (Export diagram) for inclusion in the delivered report.")
    d.h2("Representative relationships")
    rel_use = {"Local asset-to-asset": "Local relationship", "Asset-to-external/unknown": "External dependency — validate against policy", "Unmapped unicast": "Identify endpoints"}
    top = sorted(a.relationships, key=lambda r: -int(r.get("packets") or 0))[:20]
    d.table(["Endpoint A", "Endpoint B", "Protocols", "Zone pair", "Packets", "Decision / use"],
            [[[r.get("endpoint_a", ""), r.get("level_a", "")], [r.get("endpoint_b", ""), r.get("level_b", "")], r.get("protocols", ""), r.get("crossing") or "Within level", fmt_int(r.get("packets")),
              [r.get("decision", "Unknown") + (f": {r['purpose']}" if r.get("purpose") else ""), rel_use.get(r.get("category", ""), "")]] for r in top] or [["No unicast relationships observed", "", "", "", "", ""]],
            [0.20, 0.20, 0.12, 0.18, 0.08, 0.22], size=8)
    d.h2("Industrial protocol observations")
    ot_rows = [[OT_PROTOCOLS[k], ("Observed", GREEN, True), fmt_int(a.protocols[k]["flows"]), fmt_int(a.protocols[k]["packets"])] if k in a.protocols else [OT_PROTOCOLS[k], ("Not observed", MUTED), "—", "—"] for k in OT_PROTOCOLS]
    d.table(["Protocol", "Status", "Flows", "Packets"], ot_rows, [0.40, 0.20, 0.20, 0.20])
    d.muted("Not observed means not visible from the recorded collection points during the observation window. SINAUT ST7, S7comm Plus (TLS), OPC UA payloads and serial protocols are not decoded by the collector and require other evidence.")
    d.h2("IT service protocols observed")
    it_rows = [[IT_SERVICE_PROTOCOLS[k], fmt_int(v["flows"]), fmt_int(v["packets"]), ("Cleartext — review", AMBER, True) if k in CLEARTEXT_RISK else ""] for k, v in sorted(a.protocols.items()) if k in IT_SERVICE_PROTOCOLS]
    d.table(["Protocol", "Flows", "Packets", "Note"], it_rows or [["None observed", "", "", ""]], [0.40, 0.18, 0.18, 0.24])
    d.h2("Broadcast and service-discovery traffic")
    disc = sorted(a.discovery, key=lambda x: -int(x.get("packets") or 0))[:12]
    d.table(["Source", "Destination", "Protocol", "Flows", "Packets"], [[x.get("source", ""), x.get("destination", ""), x.get("protocol", ""), fmt_int(x.get("flows")), fmt_int(x.get("packets"))] for x in disc] or [["None observed", "", "", "", ""]], [0.28, 0.28, 0.20, 0.12, 0.12], size=8)
    d.muted("Discovery traffic reveals device presence and services (mDNS, SSDP, NetBIOS, LLDP, DHCP) but is not a communication relationship between two assets.")
    d.h2("Production OT analysis views")
    for line in ["Local OT asset-to-asset relationships and industrial protocol usage.",
                 "OT-to-IT and internet-bound relationships crossing defined zone boundaries.",
                 "Historian, SCADA, engineering workstation and controller dependencies.",
                 "Vendor remote-access, jump-host, cellular, radio and telemetry pathways.",
                 "Observed communications compared with an approved conduit or firewall-rule baseline."]:
        d.bullet(line)
    d.callout("Interpretation limit", "Observed traffic proves a pathway exists. It does not establish whether that communication is authorised, risky or analogous to an approved OT conduit until it is compared with the client's architecture and policy.")

    # 5 Findings ----------------------------------------------------------------------
    d.h1("5. Findings and observations register")
    if a.register_mode:
        d.para("Findings are maintained in the OT Scout register. Control deficiencies, evidence gaps, improvement opportunities and positive observations are kept as separate types so that a gap in evidence is never presented as a confirmed weakness.")
        kinds: dict[str, int] = {}
        for f in a.reportable:
            kinds[f.get("kind", "")] = kinds.get(f.get("kind", ""), 0) + 1
        d.tiles([(str(kinds.get("Control deficiency", 0)), "Control deficiencies"), (str(kinds.get("Evidence gap", 0)), "Evidence gaps"), (str(kinds.get("Improvement opportunity", 0)), "Improvements"), (str(kinds.get("Positive observation", 0)), "Positive")])
        if a.unvalidated:
            d.callout("Assessor validation required", f"{len(a.unvalidated)} finding(s) are still in Draft status: {', '.join(f['ref'] for f in a.unvalidated)}. Validate, reword or reject each before delivery.", AMBER_BG, AMBER)
        else:
            d.callout("Validation status", "All findings in the register have been validated or accepted by the assessor.", GREEN_BG, GREEN)
        if a.rejected:
            d.muted(f"Rejected and excluded from this report: {', '.join(f['ref'] for f in a.rejected)}.")
    else:
        d.para("Confirmed control deficiencies, evidence gaps and improvement opportunities are kept separate. The entries below were generated from the evidence in this data set and are drafts: the assessor must validate, reword or remove each one, and add findings from interviews, configuration review and walkdown that the collector cannot see.")
        d.callout("Assessor validation required", f"{len(a.findings)} automatically generated entr{'y' if len(a.findings) == 1 else 'ies'}. None has been reviewed by a person. Import them into the findings register to edit and validate.", AMBER_BG, AMBER)
    for f in a.reportable:
        d.h2(f"{f['ref']} — {f['title']}")
        d.labeled("Type / rating", f"{f.get('kind', '')}; {f['rating']} (evidence confidence: {f['confidence']}; recommended owner: {f['owner'] or 'unassigned'}; horizon: {f.get('horizon') or 'unassigned'}; status: {f.get('status', 'Draft')})")
        if f.get("site") or f.get("assets"):
            d.labeled("Scope", "; ".join(v for v in (f.get("site"), f.get("assets")) if v))
        d.labeled("Condition", f["condition"])
        d.labeled("Evidence", f["evidence"])
        d.labeled("Operational impact", f["impact"])
        d.labeled("Recommendation", f["recommendation"])
        d.labeled("Validation / closure", f["closure"])
        if f.get("iec62443") or f.get("attack"):
            d.labeled("Framework references", "; ".join(v for v in (f"IEC 62443: {f['iec62443']}" if f.get("iec62443") else "", f"ATT&CK for ICS: {f['attack']}" if f.get("attack") else "") if v))

    # 6 Roadmap ----------------------------------------------------------------------------
    d.h1("6. Remediation roadmap and final deliverable")
    d.para("Recommendations should be sequenced around operational risk, maintenance windows, dependencies and accountable ownership — not simply ordered by technical severity.")
    generic = {
        "Immediate / quick win": ("Approve evidence plan; obtain drawings and network exports; establish asset and communication baselines; disclose visibility limits.", "Known scope, explicit gaps, no false claim of completeness."),
        "30-90 days": ("Validate zones and conduits; review firewall and remote-access paths; document SCADA, historian and telemetry dependencies.", "Defensible current-state architecture and risk register."),
        "3-12 months": ("Implement prioritised segmentation, monitoring, access-control, lifecycle, backup/recovery and vendor-access improvements.", "Reduced operational and cyber risk with measurable ownership."),
        "Strategic": ("Maintain continuous inventory, approved communication baselines, lifecycle data and tested recovery.", "Sustainable OT security programme rather than a point-in-time report."),
    }
    if a.register_mode:
        rows = []
        for horizon, (actions, outcome) in generic.items():
            items = [f for f in a.reportable if f.get("horizon") == horizon and f.get("kind") != "Positive observation"]
            listed = "; ".join(f"{f['ref']} {f['title']}" + (f" (owner: {f['owner']})" if f.get("owner") else "") for f in items) or "No findings assigned to this horizon"
            rows.append([horizon, listed, outcome])
        d.table(["Horizon", "Findings and owners", "Expected outcome"], rows, [0.18, 0.54, 0.28])
        d.muted("Roadmap is rolled up from the horizon assigned to each finding in the register.")
    else:
        d.table(["Horizon", "Priority actions", "Expected outcome"], [[h, act, out] for h, (act, out) in generic.items()], [0.18, 0.50, 0.32])
    d.h2("Proposed full report contents")
    d.table(["Section", "Deliverable content"], [[str(i), t] for i, t in enumerate([
        "Executive summary and top risks", "Scope, assumptions, exclusions and methodology", "Site and facility validation results",
        "OT asset inventory and lifecycle observations", "SCADA, historian, telemetry and remote-access architecture",
        "Communication maps and protocol analysis", "Purdue / ISA-62443 zones, conduits and boundary controls",
        "Monitoring, logging, backup, recovery and resilience", "Detailed findings and risk register",
        "Quick-win, mid-term and long-term roadmap"], 1)] + [["A–D", "Evidence register, inventories, flow register, diagrams and checklists"]], [0.12, 0.88])
    d.h2("Automation boundary")
    d.table(["OT Scout can automate", "Assessor judgement remains required"], [[
        "Packet evidence, identity correlation, vendor lookup, passive fingerprints, protocols, relationship normalisation, coverage warnings, evidence export and draft observations.",
        "Scope, safety context, process impact, criticality, authorisation, architecture interpretation, control assessment, risk rating, remediation sequencing and ownership."]], [0.5, 0.5])

    # Appendix ---------------------------------------------------------------------------------
    d.h1("Appendix A — Basis and limitations")
    d.h2("Report limitations")
    for line in ["Passive discovery only identifies traffic visible at the collection point during the observation period.",
                 "Inactive, isolated, non-IP, encrypted, serial, radio, cellular and unmonitored devices may not be identified.",
                 "Manufacturer, model, firmware, serial number and device type may be inferred from partial evidence and require confirmation.",
                 "A vulnerability or exposure should not be asserted solely because a port, protocol or external destination was observed.",
                 "Protocol identification is port-based unless a decoded payload is listed as fingerprint evidence.",
                 "No production change should be implemented without operational review, approved change control, testing and rollback planning."]:
        d.bullet(line)
    d.h2("Source record")
    for s in a.sessions:
        d.h3(f"Session {s.get('id', '')}: {s.get('collection_point', '')} ({s.get('source_type', '')})")
        d.labeled("Assessment / site", f"{s.get('assessment', '')} / {s.get('site', '')}")
        d.labeled("Interface or file", s.get("interface", ""))
        d.labeled("Access method", s.get("access_method", ""))
        d.labeled("Capture window", f"{s.get('started_at', '')} through {s.get('ended_at') or 'still running at export'} ({fmt_duration_words(s.get('duration_seconds'))})")
        d.labeled("Evidence volume", f"{fmt_int(s.get('packets'))} packets / {fmt_int(s.get('bytes'))} bytes; third-party unicast {fmt_int(s.get('third_party_unicast'))}, local unicast {fmt_int(s.get('local_unicast'))}, broadcast/multicast {fmt_int(s.get('broadcast_multicast'))}")
    d.labeled("Export generated", generated)
    d.h2("Appendix B — IP and name evidence")
    ev_rows = []
    for x in a.assets:
        for ip in x.get("ip_evidence") or []:
            ev_rows.append([a.label(x), a.mac(x.get("mac", "")), ip.get("ip", ""), ip.get("evidence", ""), f"{ip.get('confidence', '')}%", fmt_int(ip.get("packets"))])
    if ev_rows:
        d.table(["Asset", "MAC", "IP", "Evidence", "Confidence", "Packets"], ev_rows[:120], [0.24, 0.20, 0.18, 0.18, 0.10, 0.10], size=8)
        if len(ev_rows) > 120:
            d.muted(f"{len(ev_rows) - 120} further IP evidence claims are in the assets export.")
    else:
        d.para("IP evidence detail is available in the assets export.")
    d.muted("End of generated report.")

    return d.build(title, prepared_by, f"{title} — {assessment} — {banner}")


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2:
        print("usage: python3 -m ot_scout.report assessment.json report.docx [--sanitize] [--for CLIENT] [--by ASSESSOR]")
        return 2
    data = json.loads(Path(argv[0]).read_text())
    meta = {"sanitize": "--sanitize" in argv}
    for flag, key in (("--for", "prepared_for"), ("--by", "prepared_by"), ("--title", "title"), ("--banner", "banner")):
        if flag in argv:
            meta[key] = argv[argv.index(flag) + 1]
    Path(argv[1]).write_bytes(build_report(data, meta))
    print(f"Wrote {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
