"""Where the data lives, and whose it is.

Data is kept outside the program folder, in ~/.local/share/<edition data folder>/, so updating or
deleting a checkout never touches an assessment. Live capture needs root, and `sudo` would otherwise
put everything under /root and leave files the assessor cannot open afterwards: when SUDO_USER is
set, the folder is the invoking user's, and whatever the tool creates in it is handed back to them.
"""
from __future__ import annotations

import os
import pwd
from pathlib import Path


def invoking_user(env=None, euid=None, lookup=pwd.getpwnam):
    """(uid, gid, home) of the user who ran sudo, or None when not running under sudo as root."""
    env = os.environ if env is None else env
    euid = os.geteuid() if euid is None else euid
    name = (env.get("SUDO_USER") or "").strip()
    if euid != 0 or not name or name == "root":
        return None
    try:
        entry = lookup(name)
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid, Path(entry.pw_dir)


def default_data_dir(folder: str, env=None, euid=None, lookup=pwd.getpwnam, home=None) -> Path:
    """~/.local/share/<folder> for the person actually using the tool."""
    user = invoking_user(env, euid, lookup)
    base = user[2] if user else (Path(home) if home else Path.home())
    return base / ".local" / "share" / folder


def hand_back(root, env=None, euid=None, lookup=pwd.getpwnam) -> int:
    """Give everything under `root` that root owns back to the sudo user. Returns how many paths changed."""
    user = invoking_user(env, euid, lookup)
    root = Path(root)
    if not user or not root.exists():
        return 0
    uid, gid, _ = user
    changed = 0
    targets = [root, *root.rglob("*")]
    # The chain of folders we may have created above the data folder (~/.local, ~/.local/share).
    parent = root.parent
    while parent != user[2] and user[2] in parent.parents:
        targets.append(parent)
        parent = parent.parent
    for path in targets:
        try:
            if path.is_symlink():
                continue
            if path.stat().st_uid == 0:
                os.chown(path, uid, gid)
                changed += 1
        except OSError:
            pass
    return changed
