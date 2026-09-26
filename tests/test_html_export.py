"""The single-file HTML export, rendered from the demonstration database."""
import html.parser
import tempfile
import unittest
from pathlib import Path

import demo
from ot_scout import __version__
from ot_scout.html_export import build_html


class Checker(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.external = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.scripts += 1
        for key in ("src", "href"):
            if attrs.get(key):
                self.external.append(attrs[key])


class HtmlExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = demo.build_demo(Path(cls.tmp.name) / "demo.db").store
        cls.page = build_html(cls.store, "Test Product", __version__)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_it_is_one_self_contained_file(self):
        checker = Checker()
        checker.feed(self.page)
        self.assertEqual(checker.external, [], "nothing is fetched from anywhere")
        self.assertEqual(checker.scripts, 0)
        self.assertIn("<style>", self.page)

    def test_it_says_what_generated_it(self):
        self.assertIn(f"by Test Product v{__version__}", self.page)

    def test_it_carries_the_inventory_relationships_and_findings(self):
        assets = [a for a in self.store.assets() if a.get("physical_asset")]
        self.assertIn(f"Asset inventory ({len(assets)})", self.page)
        self.assertIn("WTP-EWS01", self.page)
        self.assertIn(f"Communication relationships ({len(self.store.relationships(100000))})", self.page)
        live = [f for f in self.store.findings() if f["status"] != "Rejected"]
        self.assertIn(f"Findings ({len(live)})", self.page)
        self.assertIn(live[0]["ref"], self.page)

    def test_rejected_findings_are_left_out_and_text_is_escaped(self):
        rejected = [f for f in self.store.findings() if f["status"] == "Rejected"]
        self.assertTrue(rejected)
        self.assertNotIn(f"<td>{rejected[0]['ref']}</td>", self.page)
        self.store.save_finding({"title": "<script>alert(1)</script>", "kind": "Control deficiency", "rating": "Low", "status": "Validated"})
        page = build_html(self.store, "Test Product", __version__)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
