"""Optional modules, and the one place core code learns which of them are present.

Core never imports a module by name. `ot_scout/edition.py` lists the modules an edition ships; each
one lives in its own package beside this file and exposes `EXTENSION`, an `Extension` instance. A
listed module whose files are absent is skipped, so deleting a module's folder removes it cleanly:
its routes answer 404, its tab and settings never render, and nothing else notices.

An extension can contribute:
  - tabs (`tabs`) and page fragments (`ui.html`, split into named slots) plus a script (`ui.js`)
  - HTTP routes (`get` / `post`, returning True when they answered)
  - database tables (`schema`), added to every Store opened after it loads
  - sections of the evidence snapshot (`contribute`), fields on inventory rows (`annotate_assets`)
    and demonstration data (`seed_demo`)
"""
from __future__ import annotations

import importlib
import inspect
import re
from pathlib import Path

_LOADED: dict[str, "Extension"] = {}
ACTIVE: list["Extension"] = []

FRAGMENT = re.compile(r"<!--\s*fragment:([a-z0-9-]+)\s*-->")


class Extension:
    name = ""
    tabs: tuple = ()       # (tab id, label, id of the tab it follows)
    schema = ""            # SQL run by every Store opened after this module loads

    @property
    def folder(self) -> Path:
        return Path(inspect.getfile(type(self))).resolve().parent

    def fragments(self) -> dict[str, str]:
        """Named slices of ui.html, keyed by the slot of the core page they belong in."""
        source = self.folder / "ui.html"
        if not source.is_file():
            return {}
        parts = FRAGMENT.split(source.read_text(encoding="utf-8"))
        return {parts[i]: parts[i + 1].strip("\n") for i in range(1, len(parts) - 1, 2)}

    def script(self) -> str:
        source = self.folder / "ui.js"
        return source.read_text(encoding="utf-8") if source.is_file() else ""

    def install(self) -> None:
        """Called once, when the module is first loaded in this process."""
        if self.schema:
            from ..store import Store
            if self.schema not in Store.EXTRA_SCHEMA:
                Store.EXTRA_SCHEMA.append(self.schema)

    def attach(self, server) -> None:
        """Called for each server the module is mounted on."""

    def get(self, handler, path: str) -> bool:
        return False

    def post(self, handler, path: str) -> bool:
        return False

    def contribute(self, store, data: dict) -> None:
        """Add this module's sections to an evidence snapshot."""

    def annotate_assets(self, store, assets: list[dict]) -> list[dict]:
        """The inventory as the Inventory tab shows it; a module may add fields to each asset."""
        return assets

    def seed_demo(self, store) -> None:
        """Add this module's part of the demonstration data set."""


def load(names) -> list[Extension]:
    """The extensions for these module names, in order, skipping any whose files are absent."""
    out = []
    for name in names:
        if name in _LOADED:
            out.append(_LOADED[name])
            continue
        qualified = f"{__name__}.{name}"
        try:
            module = importlib.import_module(qualified)
        except ModuleNotFoundError as exc:
            if exc.name == qualified:
                continue
            raise
        extension = getattr(module, "EXTENSION", None)
        if extension is None:          # an emptied folder imports as a namespace package
            continue
        extension.install()
        _LOADED[name] = extension
        out.append(extension)
    return out


def activate(names) -> list[Extension]:
    """Load an edition's modules and make them the ones evidence snapshots consult."""
    ACTIVE[:] = load(names)
    return list(ACTIVE)


def contribute(store, data: dict) -> None:
    for extension in ACTIVE:
        extension.contribute(store, data)


def seed_demo(store) -> None:
    for extension in ACTIVE:
        extension.seed_demo(store)
