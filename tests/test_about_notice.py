"""The AGPL asks an interactive UI to carry the licence notice. Make sure a redesign cannot quietly drop it."""
import unittest

from ot_scout import edition
from ot_scout.web import render_page


class AboutNoticeTests(unittest.TestCase):
    def setUp(self):
        self.markup = render_page(edition, [], "token").decode("utf-8")

    def test_notice_is_in_the_about_dialog(self):
        about = self.markup[self.markup.index('id="aboutDialog"'):]
        about = about[:about.index("</dialog>")]
        self.assertIn('id="aboutLicence"', about, "the licence notice must sit inside the About dialog")

    def test_notice_carries_every_required_element(self):
        notice = self.markup[self.markup.index('id="aboutLicence"'):]
        notice = notice[:notice.index("</div>")]
        for required in ("Copyright", "no warranty", "Affero", "redistribute", "LICENSE"):
            self.assertIn(required, notice, f"licence notice is missing: {required}")

    def test_notice_links_to_the_licence(self):
        self.assertIn("gnu.org/licenses/agpl-3.0", self.markup)

    def test_page_names_the_edition_and_version(self):
        from ot_scout import __version__
        self.assertIn(f"<title>{edition.NAME} v{__version__}</title>", self.markup)
        self.assertIn('<footer class="foot">', self.markup)
        self.assertNotIn("{{", self.markup, "every placeholder is filled")
        self.assertNotIn("<!--slot:", self.markup)

    def test_tab_labels_follow_the_edition(self):
        import re
        tabs = dict(re.findall(r'<button data-tab="([a-z]+)"[^>]*>([^<]+)</button>', self.markup))
        for tab_id, label in (getattr(edition, "TAB_LABELS", {}) or {}).items():
            self.assertEqual(tabs.get(tab_id), label)


class PageWiringTests(unittest.TestCase):
    """Every element the page's script looks up by id is on the page it is served with. A lookup that
    finds nothing throws, and a throw at load stops everything after it."""

    OPTIONAL = {"guideLink"}      # only rendered when the assessment guide ships; the script checks first

    def test_core_script_finds_every_element_it_uses(self):
        import re
        page = render_page(edition, [], "token").decode("utf-8") if not edition.MODULES else None
        if page is None:
            from ot_scout.modules import load
            page = render_page(edition, load(edition.MODULES), "token").decode("utf-8")
        ids = set(re.findall(r"\$\('([A-Za-z0-9_-]+)'\)", page))
        missing = sorted(i for i in ids - self.OPTIONAL if f'id="{i}"' not in page)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
