"""The AGPL asks an interactive UI to carry the licence notice. Make sure a redesign cannot quietly drop it."""
import pathlib
import unittest

INDEX = pathlib.Path(__file__).resolve().parent.parent / "ot_scout" / "static" / "index.html"


class AboutNoticeTests(unittest.TestCase):
    def setUp(self):
        self.markup = INDEX.read_text(encoding="utf-8")

    def test_notice_is_in_the_about_dialog(self):
        self.assertIn('id="aboutLicence"', self.markup)
        about = self.markup[self.markup.index('id="aboutDialog"'):]
        about = about[:about.index("</dialog>")]
        self.assertIn('id="aboutLicence"', about, "the licence notice must sit inside the About dialog")

    def test_notice_carries_every_required_element(self):
        notice = self.markup[self.markup.index('id="aboutLicence"'):]
        notice = notice[:notice.index("</div>")]
        for required in ("Higate Ventures LLC", "no warranty", "Affero", "redistribute", "LICENSE"):
            self.assertIn(required, notice, f"licence notice is missing: {required}")

    def test_notice_links_to_the_licence_and_the_source(self):
        self.assertIn("gnu.org/licenses/agpl-3.0", self.markup)
        self.assertIn("github.com/cvhyatt-code/ot-scout", self.markup)


if __name__ == "__main__":
    unittest.main()
