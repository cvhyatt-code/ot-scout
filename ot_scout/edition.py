"""Everything that differs between editions, in one file."""

NAME = "OT Scout Community Edition"
TAGLINE = "Passive OT/ICS assessment"

# "" keeps the built-in look; any other value loads static/theme-<THEME>.css after it.
THEME = "plain"

# Data lives in ~/.local/share/<DATA_DIR_NAME>/ unless --data-dir says otherwise.
DATA_DIR_NAME = "ot-scout"

# Shown at the foot of every page. {name} and {version} are filled in; this is HTML.
FOOTER = ('{name} v{version} &middot; AGPL-3.0 &middot; '
          '<a href="https://github.com/cvhyatt-code/ot-scout/tree/v{version}" target="_blank" rel="noopener">Source</a>')

# The licence notice in the About dialog (HTML).
ABOUT_NOTICE = (
    'Copyright holders are named in the <code>NOTICE</code> file. {name} comes with <strong>absolutely no '
    'warranty</strong>. It is free software under the <a href="https://www.gnu.org/licenses/agpl-3.0.html" '
    'target="_blank" rel="noopener">GNU Affero General Public License, version 3 or later</a>, and you are '
    'welcome to redistribute it under those terms; the full licence is in the <code>LICENSE</code> file. '
    'Source code for this version: <a href="https://github.com/cvhyatt-code/ot-scout/tree/v{version}" '
    'target="_blank" rel="noopener">github.com/cvhyatt-code/ot-scout</a>.'
)

# Core tab labels this edition renames, by tab id. The Report tab holds only exports here.
TAB_LABELS = {"report": "Export"}

# Optional modules under ot_scout/modules/. This edition ships none.
MODULES = ()
