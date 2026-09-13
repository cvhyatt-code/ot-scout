"""One engagement, one database.

The failure this prevents is a customer's assets, sessions and findings appearing in a different
customer's report. Everything here is about keeping those apart, and about the switch target coming
from the browser rather than from us.
"""
import json
import sqlite3
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ot_scout.capture import CaptureManager
from ot_scout.store import Store
from ot_scout.web import AppServer, Handler, describe_database


class AliveThread:
    @staticmethod
    def is_alive():
        return True


def server_for(tmp: Path) -> AppServer:
    store = Store(str(tmp / "ot_scout_v4.db"))
    server = AppServer(("127.0.0.1", 0), Handler, store, CaptureManager(store))
    server.main_database = str(tmp / "ot_scout_v4.db")
    server.demo_database = str(tmp / "demo.db")
    return server


class DescribeDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_an_assessment_database_describes_itself(self):
        store = Store(str(self.dir / "a.db"))
        store.meta_set("engagement", "Northgate Chemicals")
        info = describe_database(self.dir / "a.db")
        self.assertEqual(info["name"], "Northgate Chemicals")
        self.assertEqual(info["sessions"], 0)

    def test_it_falls_back_to_the_first_session_name(self):
        """Databases predating engagements still say what they are."""
        store = Store(str(self.dir / "b.db"))
        store.begin_session("Riverbend WTP — OT assessment", "Main", "Core SPAN", "eth0", "live", "SPAN")
        self.assertEqual(describe_database(self.dir / "b.db")["name"], "Riverbend WTP — OT assessment")

    def test_a_foreign_sqlite_file_is_not_an_engagement(self):
        db = sqlite3.connect(str(self.dir / "other.db"))
        db.execute("CREATE TABLE recipes (id INTEGER)")
        db.commit(); db.close()
        self.assertIsNone(describe_database(self.dir / "other.db"))

    def test_rubbish_is_not_an_engagement(self):
        (self.dir / "junk.db").write_bytes(b"not a database at all")
        self.assertIsNone(describe_database(self.dir / "junk.db"))

    def test_listing_does_not_create_a_schema(self):
        """Reading the list must not adopt an unrelated file by writing tables into it."""
        target = self.dir / "other.db"
        db = sqlite3.connect(str(target))
        db.execute("CREATE TABLE recipes (id INTEGER)")
        db.commit(); db.close()
        before = target.read_bytes()
        describe_database(target)
        self.assertEqual(target.read_bytes(), before)


class EngagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.server = server_for(self.dir)

    def tearDown(self):
        self.server.server_close()
        self.tmp.cleanup()

    def test_a_new_engagement_gets_its_own_database_and_becomes_current(self):
        status = self.server.new_engagement("Northgate Chemicals — Plant 3")
        self.assertEqual(status["engagement"], "Northgate Chemicals — Plant 3")
        self.assertTrue(status["file"].endswith(".db"))
        self.assertIn("northgate-chemicals-plant-3", status["file"])
        self.assertTrue((self.dir / status["file"]).is_file())
        self.assertEqual(self.server.store.engagement_name(), "Northgate Chemicals — Plant 3")

    def test_the_previous_engagement_is_untouched(self):
        self.server.store.begin_session("First job", "Site A", "SPAN", "eth0", "live", "SPAN")
        first = Path(self.server.store.path).name
        self.server.new_engagement("Second job")
        self.assertNotEqual(Path(self.server.store.path).name, first)
        self.assertEqual(self.server.store.counts()["sessions"], 0)
        self.assertEqual(describe_database(self.dir / first)["sessions"], 1)

    def test_names_that_would_be_bad_filenames_are_slugified(self):
        status = self.server.new_engagement("  ../../Acme & Co / Plant #2  ")
        self.assertNotIn("/", status["file"])
        self.assertNotIn("..", status["file"])
        self.assertEqual(Path(self.dir / status["file"]).parent, self.dir)
        self.assertEqual(status["engagement"], "../../Acme & Co / Plant #2")

    def test_two_engagements_with_the_same_name_do_not_collide(self):
        a = self.server.new_engagement("Same Name")["file"]
        b = self.server.new_engagement("Same Name")["file"]
        self.assertNotEqual(a, b)
        self.assertTrue((self.dir / a).is_file() and (self.dir / b).is_file())

    def test_an_empty_name_is_refused(self):
        with self.assertRaises(ValueError):
            self.server.new_engagement("   ")

    def test_a_running_capture_blocks_a_new_engagement(self):
        self.server.capture.thread = AliveThread()
        with self.assertRaises(ValueError) as ctx:
            self.server.new_engagement("While capturing")
        self.assertIn("Stop the capture", str(ctx.exception))

    def test_listing_shows_engagements_and_marks_the_current_one(self):
        self.server.store.begin_session("First job", "Site A", "SPAN", "eth0", "live", "SPAN")
        self.server.new_engagement("Second job")
        names = {e["name"]: e for e in self.server.engagements()}
        self.assertIn("Second job", names)
        self.assertIn("First job", names)
        self.assertTrue(names["Second job"]["current"])
        self.assertFalse(names["First job"]["current"])
        self.assertEqual(names["First job"]["sessions"], 1)

    def test_the_demo_set_is_not_listed_as_an_engagement(self):
        Store(self.server.demo_database).meta_set("engagement", "demo")
        self.assertNotIn("demo.db", [e["file"] for e in self.server.engagements()])

    def test_switching_back_restores_that_engagement(self):
        self.server.store.begin_session("First job", "Site A", "SPAN", "eth0", "live", "SPAN")
        first = Path(self.server.store.path).name
        self.server.new_engagement("Second job")
        status = self.server.switch_database(first)
        self.assertEqual(status["file"], first)
        self.assertEqual(self.server.store.counts()["sessions"], 1)


class SwitchTargetSafetyTests(unittest.TestCase):
    """The switch target is a filename supplied by the browser."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "data"
        self.dir.mkdir()
        self.outside = Path(self.tmp.name) / "elsewhere.db"
        Store(str(self.outside))                      # a real assessment database, outside the data dir
        self.server = server_for(self.dir)

    def tearDown(self):
        self.server.server_close()
        self.tmp.cleanup()

    def test_a_path_outside_the_data_directory_is_refused(self):
        for target in (str(self.outside), "../elsewhere.db", "../../elsewhere.db",
                       "/etc/passwd", "subdir/other.db", "data/../../elsewhere.db"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.server.switch_database(target)

    def test_a_missing_file_in_the_data_directory_is_refused(self):
        with self.assertRaises(ValueError):
            self.server.switch_database("nothing-here.db")

    def test_a_non_database_target_is_refused(self):
        with self.assertRaises(ValueError):
            self.server.switch_database("index.html")

    def test_the_current_engagement_is_unchanged_after_a_refused_switch(self):
        before = self.server.store.path
        for target in ("../elsewhere.db", "nope.db", "index.html"):
            with self.assertRaises(ValueError):
                self.server.switch_database(target)
        self.assertEqual(self.server.store.path, before)


class EngagementApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.server = server_for(cls.dir)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def call(self, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_create_list_and_switch_over_http(self):
        status, d = self.call("/api/engagements/new", {"name": "HTTP Engagement"})
        self.assertEqual(status, 200, d)
        created = d["file"]
        status, d = self.call("/api/engagements")
        self.assertEqual(status, 200)
        self.assertIn("HTTP Engagement", [e["name"] for e in d["engagements"]])
        status, d = self.call("/api/database/switch", {"target": created})
        self.assertEqual(status, 200, d)
        self.assertEqual(d["file"], created)

    def test_a_traversal_target_is_rejected_over_http(self):
        status, d = self.call("/api/database/switch", {"target": "../../../etc/passwd"})
        self.assertEqual(status, 400)
        self.assertIn("Unknown data set", d["error"])

    def test_status_carries_the_engagement_name(self):
        self.call("/api/engagements/new", {"name": "Named In Status"})
        status, d = self.call("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(d["engagement"], "Named In Status")


if __name__ == "__main__":
    unittest.main()


class EngagementDetailTests(unittest.TestCase):
    """You should be able to see exactly what an engagement owns before deciding to remove it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "captures").mkdir()
        self.server = server_for(self.dir)

    def tearDown(self):
        self.server.server_close()
        self.tmp.cleanup()

    def seed(self, name, captures=2):
        """An engagement with sessions and real capture files on disk."""
        status = self.server.new_engagement(name)
        store = self.server.store
        for i in range(captures):
            sid = store.begin_session(name, "Plant", f"SPAN {i}", "eth0", "live", "SPAN")
            pcap = self.dir / "captures" / f"{Path(status['file']).stem}-session-{sid:03d}.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 4096)
            store.set_session_pcap(sid, str(pcap))
        return status["file"]

    def test_detail_lists_the_database_and_every_capture(self):
        f = self.seed("Acme Water", captures=2)
        d = self.server.engagement_detail(f)
        self.assertEqual(d["name"], "Acme Water")
        self.assertEqual(len(d["sessions"]), 2)
        self.assertTrue(all(s["capture"] and not s["capture"]["missing"] for s in d["sessions"]))
        self.assertEqual(d["capture_bytes"], 2 * 4100)
        self.assertGreater(d["database_bytes"], 0)
        self.assertEqual(d["total_bytes"], d["database_bytes"] + d["capture_bytes"])

    def test_a_capture_deleted_behind_our_back_is_reported_missing(self):
        f = self.seed("Acme Water", captures=1)
        Path(self.server.engagement_detail(f)["sessions"][0]["capture"]["name"])
        next(( self.dir / "captures").glob("*.pcap")).unlink()
        d = self.server.engagement_detail(f)
        self.assertTrue(d["sessions"][0]["capture"]["missing"])
        self.assertEqual(d["capture_bytes"], 0)

    def test_an_imported_session_has_no_capture_file(self):
        self.server.new_engagement("Imported job")
        self.server.store.begin_session("Imported job", "Plant", "handed to me", "vendor.pcap", "pcap", "Imported PCAP")
        d = self.server.engagement_detail(Path(self.server.store.path).name)
        self.assertIsNone(d["sessions"][0]["capture"])

    def test_detail_refuses_a_path_outside_the_data_directory(self):
        for target in ("../elsewhere.db", "/etc/passwd", "nope.db"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.server.engagement_detail(target)

    def test_detail_refuses_the_demo_set(self):
        Store(self.server.demo_database)
        with self.assertRaises(ValueError):
            self.server.engagement_detail("demo.db")


class EngagementDeleteTests(EngagementDetailTests):
    def test_delete_removes_the_database_and_its_captures(self):
        keep = self.seed("Keep This", captures=2)
        doomed = self.seed("Delete This", captures=3)
        self.server.switch_database(keep)                       # never delete what you are standing in
        result = self.server.delete_engagement(doomed, "Delete This")
        self.assertEqual(result["captures_removed"], 3)
        self.assertFalse((self.dir / doomed).exists())
        self.assertEqual(len(list((self.dir / "captures").glob("*.pcap"))), 2, "the other engagement's captures must survive")
        self.assertNotIn(doomed, [e["file"] for e in self.server.engagements()])

    def test_the_engagement_you_are_in_cannot_be_deleted(self):
        f = self.seed("Current Job", captures=1)
        with self.assertRaises(ValueError) as ctx:
            self.server.delete_engagement(f, "Current Job")
        self.assertIn("Switch to a different engagement", str(ctx.exception))
        self.assertTrue((self.dir / f).exists())

    def test_the_name_must_match_exactly(self):
        keep = self.seed("Keep This", captures=1)
        doomed = self.seed("Delete This", captures=1)
        self.server.switch_database(keep)
        for wrong in ("delete this", "Delete", "", "Keep This", doomed):
            with self.subTest(confirm=wrong), self.assertRaises(ValueError):
                self.server.delete_engagement(doomed, wrong)
        self.assertTrue((self.dir / doomed).exists())
        self.assertEqual(len(list((self.dir / "captures").glob("*.pcap"))), 2)

    def test_a_running_capture_blocks_deletion(self):
        keep = self.seed("Keep This", captures=1)
        doomed = self.seed("Delete This", captures=1)
        self.server.switch_database(keep)
        self.server.capture.thread = AliveThread()
        with self.assertRaises(ValueError) as ctx:
            self.server.delete_engagement(doomed, "Delete This")
        self.assertIn("Stop the capture", str(ctx.exception))
        self.assertTrue((self.dir / doomed).exists())

    def test_a_capture_path_outside_the_captures_directory_is_never_unlinked(self):
        """The path comes out of a database; treat it as untrusted anyway."""
        keep = self.seed("Keep This", captures=1)
        doomed = self.seed("Delete This", captures=0)
        outside = self.dir.parent / "not-ours.pcap"
        outside.write_bytes(b"important")
        sid = self.server.store.begin_session("Delete This", "Plant", "SPAN", "eth0", "live", "SPAN")
        self.server.store.set_session_pcap(sid, str(outside))
        self.server.switch_database(keep)
        result = self.server.delete_engagement(doomed, "Delete This")
        self.assertTrue(outside.is_file(), "a path outside data/captures must be left alone")
        self.assertEqual(result["captures_removed"], 0)
        self.assertEqual(result["captures_kept"], 1)

    def test_traversal_targets_are_refused(self):
        for target in ("../elsewhere.db", "/etc/passwd", "missing.db"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.server.delete_engagement(target, "anything")

    def test_export_timestamp_is_reported_when_present(self):
        f = self.seed("Exported Job", captures=0)
        self.assertEqual(self.server.engagement_detail(f)["exported_at"], "")
        self.server.store.meta_set("evidence_exported_at", "2026-09-13T21:00:00+0000")
        self.assertTrue(self.server.engagement_detail(f)["exported_at"].startswith("2026-09-13"))
