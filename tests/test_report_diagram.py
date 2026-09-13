"""The Purdue diagram that is drawn into the Word report.

The report cannot embed the SVG the app exports — Word wants a raster fallback and this project has no
renderer — so the diagram is rebuilt as native Word shapes from the same `zones` structure the report's
tables are built from. That shared source is the whole point of the feature and the thing these tests
guard: the numbered conduits in the picture have to be the rows of the boundary-crossing table beneath
it, in the same order, or the diagram is quietly lying to a client about which crossing is which.
"""
import unittest
import xml.dom.minidom

from ot_scout.report import BAND_ORDER, Doc, purdue_layout


def zones(levels=None, pairs=None, **extra):
    """A `zone_summary`-shaped dict with only the keys the layout reads."""
    out = {"levels": {lv: {"assets": len(names), "zones": [], "names": list(names)}
                      for lv, names in (levels or {}).items()},
           "pairs": list(pairs or [])}
    out.update(extra)
    return out


def pair(a, b, **decisions):
    counts = {d: 0 for d in ("Unknown", "Approved", "Tolerated", "Unexpected")}
    counts.update(decisions or {"Approved": 1})
    return {"level_a": a, "level_b": b, "crossing": f"{a} to {b}", "relationships": 1,
            "packets": 1, "protocols": "Modbus/TCP", "decisions": counts}


def texts(layout):
    return [s["s"] for s in layout["shapes"] if s["t"] == "text"]


class PurdueLayoutTests(unittest.TestCase):
    def test_no_levels_draws_nothing(self):
        self.assertIsNone(purdue_layout({}))
        self.assertIsNone(purdue_layout({"levels": {}, "pairs": []}))

    def test_bands_are_ordered_plant_floor_last(self):
        layout = purdue_layout(zones({"Level 3": ["HMI"], "Level 0": ["Pump"], "Industrial DMZ": ["Historian"]}))
        labels = [t for t in texts(layout) if t in BAND_ORDER]
        self.assertEqual(labels, ["Industrial DMZ", "Level 3", "Level 0"])
        tops = {s["s"]: s["y"] for s in layout["shapes"] if s["t"] == "text" and s["s"] in BAND_ORDER}
        self.assertLess(tops["Industrial DMZ"], tops["Level 3"])
        self.assertLess(tops["Level 3"], tops["Level 0"])

    def test_external_band_appears_only_when_a_pair_reaches_outside(self):
        inside = purdue_layout(zones({"Level 3": ["HMI"]}, [pair("Level 3", "Level 0")]))
        self.assertNotIn("External", texts(inside))
        outside = purdue_layout(zones({"Level 3": ["HMI"]}, [pair("External", "Level 3")]))
        self.assertIn("External", texts(outside))
        self.assertIn("Endpoints outside the assessed network", texts(outside))

    def test_conduits_are_the_crossing_rows_in_table_order(self):
        rows = [pair("Level 3", "Level 0"), pair("Level 2", "Level 2"), pair("Industrial DMZ", "Level 3")]
        layout = purdue_layout(zones({"Level 0": ["Pump"], "Level 2": ["PLC"], "Level 3": ["HMI"],
                                      "Industrial DMZ": ["Historian"]}, rows))
        # The within-level row has no boundary to draw, so it is not numbered.
        self.assertEqual(layout["conduits"], 2)
        badges = [t for t in texts(layout) if t.isdigit()]
        self.assertEqual(badges, ["1", "2"])
        # Badge 1 spans Level 3 to Level 0; badge 2 spans Industrial DMZ to Level 3. Taller span first.
        spans = [s for s in layout["shapes"] if s["t"] == "line"]
        self.assertEqual(len(spans), 2)
        self.assertGreater(spans[0]["y2"] - spans[0]["y1"], spans[1]["y2"] - spans[1]["y1"])

    def test_a_pair_naming_a_level_that_has_no_band_is_skipped(self):
        layout = purdue_layout(zones({"Level 3": ["HMI"]}, [pair("Level 3", "Nowhere")]))
        self.assertEqual(layout["conduits"], 0)

    def test_conduit_colour_follows_the_worst_decision_on_the_pair(self):
        def colour(**decisions):
            layout = purdue_layout(zones({"Level 3": ["HMI"], "Level 0": ["Pump"]},
                                         [pair("Level 3", "Level 0", **decisions)]))
            return [s for s in layout["shapes"] if s["t"] == "line"][0]["color"]

        self.assertEqual(colour(Approved=4), "#18794e")
        self.assertEqual(colour(Approved=4, Tolerated=1), "#9a6700")
        self.assertEqual(colour(Approved=4, Tolerated=1, Unknown=1), "#617181")
        self.assertEqual(colour(Approved=4, Tolerated=1, Unknown=1, Unexpected=1), "#b42318")

    def test_a_crowded_level_overflows_into_a_count_rather_than_off_the_page(self):
        names = [f"Device {i}" for i in range(40)]
        layout = purdue_layout(zones({"Level 2": names}))
        shown = [t for t in texts(layout) if t.startswith("Device ")]
        overflow = [t for t in texts(layout) if t.endswith(" more")]
        self.assertEqual(len(overflow), 1)
        self.assertEqual(len(shown) + int(overflow[0][1:-5]), len(names))
        self.assertLessEqual(max(s["y"] + s.get("h", 0) for s in layout["shapes"]), layout["height"])

    def test_a_long_asset_name_is_shortened_not_clipped(self):
        layout = purdue_layout(zones({"Level 1": ["Filter backwash valve controller 7"]}))
        label = [t for t in texts(layout) if t.startswith("Filter")][0]
        self.assertTrue(label.endswith("…"), label)
        self.assertLessEqual(len(label), 17)

    def test_the_drawing_fits_the_page_it_is_printed_on(self):
        # The report is portrait Letter with one-inch side margins: 6.5in of text width, and a diagram
        # taller than the text height would push itself onto a page of its own.
        layout = purdue_layout(zones({lv: [f"Asset {i}" for i in range(9)] for lv in BAND_ORDER[1:]},
                                     [pair("External", "Level 4")] + [pair("Level 3", "Level 0")] * 9))
        self.assertLessEqual(layout["width"], 660)
        self.assertLessEqual(layout["height"], 9 * 96)


class DiagramMarkupTests(unittest.TestCase):
    def _drawing(self, layout):
        doc = Doc()
        doc.diagram(layout)
        return doc.body[-1]

    def test_every_primitive_becomes_one_shape(self):
        layout = purdue_layout(zones({"Level 3": ["HMI"], "Level 0": ["Pump"]}, [pair("Level 3", "Level 0")]))
        self.assertEqual(self._drawing(layout).count("<wps:wsp>"), len(layout["shapes"]))

    def test_the_group_is_not_scaled(self):
        # chExt must equal ext. Word scales shapes to a mismatched child space but does not scale the
        # text inside them, which silently leaves every label at the wrong size.
        layout = purdue_layout(zones({"Level 3": ["HMI"]}))
        xml = self._drawing(layout)
        ext = f'cx="{layout["width"] * Doc.EMU}" cy="{layout["height"] * Doc.EMU}"'
        self.assertIn(f"<a:ext {ext}/>", xml)
        self.assertIn(f"<a:chExt {ext}/>", xml)

    def test_the_drawing_is_well_formed_inside_a_document(self):
        layout = purdue_layout(zones({"Level 3": ["HMI & Co"], "Level 0": ["Pump <1>"]},
                                     [pair("Level 3", "Level 0")]))
        doc = Doc()
        doc.diagram(layout)
        raw = doc.build("T", "A", "F")
        import io, zipfile
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            document = z.read("word/document.xml").decode("utf-8")
        xml.dom.minidom.parseString(document)
        self.assertIn("HMI &amp; Co", document)
        self.assertNotIn("Pump <1>", document)

    def test_shape_ids_are_unique_across_two_diagrams_in_one_document(self):
        layout = purdue_layout(zones({"Level 3": ["HMI"]}))
        doc = Doc()
        doc.diagram(layout)
        doc.diagram(layout)
        xml_body = "".join(doc.body)
        ids = [chunk.split('"')[0] for part in ('<wps:cNvPr id="', '<wp:docPr id="')
               for chunk in xml_body.split(part)[1:]]
        self.assertEqual(len(ids), len(set(ids)))


class ReportIntegrationTests(unittest.TestCase):
    def test_a_report_with_zones_carries_the_drawing(self):
        import io, zipfile
        from ot_scout.report import build_report
        data = {"assessments": [], "assets": [], "relationships": [], "findings": [],
                "zones": zones({"Level 3": ["HMI"], "Level 0": ["Pump"]}, [pair("Level 3", "Level 0")],
                               assigned=2, physical=2, infrastructure=0)}
        raw = build_report(data, {})
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            document = z.read("word/document.xml").decode("utf-8")
        xml.dom.minidom.parseString(document)
        self.assertIn("<wp:inline", document)
        self.assertIn("Purdue zone diagram", document)

    def test_a_report_without_zones_carries_no_drawing(self):
        import io, zipfile
        from ot_scout.report import build_report
        raw = build_report({"assessments": [], "assets": [], "relationships": [], "findings": []}, {})
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            document = z.read("word/document.xml").decode("utf-8")
        self.assertNotIn("<wp:inline", document)


if __name__ == "__main__":
    unittest.main()
