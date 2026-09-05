import socket
import struct
import tempfile
import unittest
from pathlib import Path

from ot_scout.parser import parse_ethernet
from ot_scout.store import Store


def _frame(dst_mac, src_mac, src_ip, dst_ip, dport):
    m = lambda s: bytes.fromhex(s.replace(":", ""))
    ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
    ip[12:16] = socket.inet_aton(src_ip); ip[16:20] = socket.inet_aton(dst_ip)
    tcp = struct.pack("!HHIIHHHH", 50000, dport, 0, 0, 0x5002, 1024, 0, 0)
    return m(dst_mac) + m(src_mac) + struct.pack("!H", 0x0800) + bytes(ip) + tcp


class FindingLinkTests(unittest.TestCase):
    PLC, HMI, ERP, GW = "00:11:22:00:00:01", "00:11:22:00:00:02", "00:11:22:00:00:03", "00:aa:bb:cc:dd:ee"

    def _store(self, tmp):
        store = Store(Path(tmp) / "t.db")
        s = store.begin_session("A", "S", "SPAN", "eth0", "live", "Configured SPAN/mirror")
        rec = lambda dm, sm, sip, dip, dport: store.record(s, parse_ethernet(_frame(dm, sm, sip, dip, dport), 2.0))
        rec(self.PLC, self.HMI, "10.0.1.20", "10.0.1.10", 502); rec(self.HMI, self.PLC, "10.0.1.10", "10.0.1.20", 50000)
        rec(self.PLC, self.ERP, "10.0.5.5", "10.0.1.10", 502); rec(self.ERP, self.PLC, "10.0.1.10", "10.0.5.5", 50000)
        rec(self.GW, self.HMI, "10.0.1.20", "8.8.8.8", 443)
        store.end_session(s)
        ids = {a["mac"]: a["id"] for a in store.assets()}
        store.update_asset(ids[self.PLC], {"purdue_level": "Level 1"})
        store.update_asset(ids[self.HMI], {"purdue_level": "Level 2"})
        store.update_asset(ids[self.ERP], {"purdue_level": "Level 4"})
        by_pair = {tuple(sorted((r["level_a"], r["level_b"]))): r for r in store.relationships()}
        bypass, ext = by_pair[("Level 1", "Level 4")], by_pair[("External", "Level 2")]
        store.save_conduit(bypass["key_a"], bypass["key_b"], {"decision": "Unexpected", "purpose": "ERP polling PLC"})
        store.save_conduit(ext["key_a"], ext["key_b"], {"decision": "Unexpected", "purpose": "HMI to internet"})
        return store, ids, bypass, ext

    def test_drafts_are_split_by_crossing_and_carry_links(self):
        from ot_scout.report import Analysis, collect
        with tempfile.TemporaryDirectory() as tmp:
            store, ids, bypass, ext = self._store(tmp)
            drafts = {d["title"]: d for d in Analysis(collect(store), False).drafts}
            self.assertIn("Direct OT-to-enterprise communications bypass the industrial DMZ", drafts)
            self.assertIn("OT assets communicate directly with external or internet endpoints", drafts)
            self.assertNotIn("Communications marked unexpected against the conduit baseline", drafts)  # nothing left over
            d = drafts["Direct OT-to-enterprise communications bypass the industrial DMZ"]
            self.assertEqual(d["confidence"], "High")  # an Unexpected decision raises it from Moderate
            kinds = {(l["kind"], l["key"]) for l in d["links"]}
            self.assertIn(("relationship", Store.relationship_key(bypass["key_a"], bypass["key_b"])), kinds)
            self.assertIn(("pair", Store.pair_key("Level 4", "Level 1")), kinds)
            self.assertIn(("asset", str(ids[self.PLC])), kinds)
            self.assertIn(("asset", str(ids[self.ERP])), kinds)
            self.assertTrue(d["iec62443"])  # framework refs still resolve for the split drafts
            self.assertTrue(drafts["OT assets communicate directly with external or internet endpoints"]["attack"])

    def test_import_links_survive_retitle_and_lookup_by_pair(self):
        from ot_scout.report import Analysis, collect
        with tempfile.TemporaryDirectory() as tmp:
            store, ids, bypass, ext = self._store(tmp)
            drafts = Analysis(collect(store), False).drafts
            n = store.import_draft_findings(drafts)
            self.assertGreaterEqual(n, 2)
            self.assertEqual(store.import_draft_findings(drafts), 0)
            reg = {f["draft_key"]: f for f in store.findings()}
            self.assertIn("dmz-bypass", reg)
            self.assertTrue(reg["dmz-bypass"]["links"])
            # assessor retitles; a second import must not duplicate it
            store.save_finding({"id": reg["dmz-bypass"]["id"], "title": "Enterprise hosts reach PLCs directly"})
            self.assertEqual(store.import_draft_findings(drafts), 0)
            # lookup from the zone-pair table / diagram
            hits = store.findings_for("pair", "Level 1|Level 4")            # either order normalises
            self.assertEqual([f["draft_key"] for f in hits], ["dmz-bypass"])
            hits = store.findings_for("relationship", f"{ext['key_a']}|{ext['key_b']}")
            self.assertEqual([f["draft_key"] for f in hits], ["unexpected-external"])
            self.assertEqual(store.findings_for("pair", "Level 1|Level 2"), [])   # approved-by-silence pair: no finding
            hits = store.findings_for("asset", str(ids[self.PLC]))
            self.assertEqual({f["draft_key"] for f in hits}, {"dmz-bypass"})
            # manual link / unlink
            manual = store.save_finding({"title": "Manual", "links": [{"kind": "pair", "key": "Level 2|Level 1"}]})
            self.assertEqual(manual["links"], [{"kind": "pair", "key": Store.pair_key("Level 1", "Level 2")}])  # order normalised
            self.assertEqual([f["id"] for f in store.findings_for("pair", "Level 1|Level 2")], [manual["id"]])
            store.unlink_finding(manual["id"], "pair", "Level 1|Level 2")
            self.assertEqual(store.findings_for("pair", "Level 1|Level 2"), [])
            with self.assertRaises(ValueError):
                store.link_finding(manual["id"], "bogus", "x")
            # delete cascades
            store.delete_finding(manual["id"])
            with store.connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM finding_links WHERE finding_id=?", (manual["id"],)).fetchone()[0], 0)

    def test_legacy_register_rows_are_backfilled_by_title(self):
        from ot_scout.report import Analysis, collect
        with tempfile.TemporaryDirectory() as tmp:
            store, ids, bypass, ext = self._store(tmp)
            drafts = Analysis(collect(store), False).drafts
            title = drafts[0]["title"]
            # a register written before draft_key existed
            store.save_finding({"title": title, "source": "OT Scout draft"})
            store.import_draft_findings(drafts)
            rows = [f for f in store.findings() if f["title"] == title]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["draft_key"], Store.draft_key_for(drafts[0]))


if __name__ == "__main__":
    unittest.main()
