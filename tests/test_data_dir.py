"""Data lives outside the program folder, and under sudo it belongs to the person who ran sudo."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ot_scout import edition
from ot_scout.paths import default_data_dir, hand_back, invoking_user

PROGRAM = Path(__file__).resolve().parent.parent


def fake_user(name):
    if name != "assessor":
        raise KeyError(name)
    return SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir="/home/assessor")


class DataDirTests(unittest.TestCase):
    def test_default_is_outside_the_program_folder(self):
        path = default_data_dir(edition.DATA_DIR_NAME, env={}, euid=1000, home="/home/me")
        self.assertEqual(path, Path("/home/me/.local/share") / edition.DATA_DIR_NAME)
        real = default_data_dir(edition.DATA_DIR_NAME).resolve()
        self.assertNotIn(PROGRAM, [real, *real.parents])

    def test_under_sudo_it_follows_sudo_user(self):
        path = default_data_dir("ot-scout", env={"SUDO_USER": "assessor"}, euid=0, lookup=fake_user, home="/root")
        self.assertEqual(path, Path("/home/assessor/.local/share/ot-scout"))

    def test_sudo_user_is_ignored_unless_we_are_root(self):
        path = default_data_dir("ot-scout", env={"SUDO_USER": "assessor"}, euid=1000, lookup=fake_user, home="/home/me")
        self.assertEqual(path, Path("/home/me/.local/share/ot-scout"))

    def test_root_as_sudo_user_or_an_unknown_user_changes_nothing(self):
        for env in ({"SUDO_USER": "root"}, {"SUDO_USER": "nobody-here"}, {}):
            self.assertIsNone(invoking_user(env=env, euid=0, lookup=fake_user), env)

    def test_hand_back_is_a_no_op_without_sudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.db").write_text("x")
            self.assertEqual(hand_back(tmp, env={}, euid=os.geteuid()), 0)

    @unittest.skipUnless(os.geteuid() == 0, "chown needs root")
    def test_hand_back_gives_root_owned_files_to_the_sudo_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "data"
            (target / "captures").mkdir(parents=True)
            (target / "captures" / "s.pcap").write_bytes(b"x")
            changed = hand_back(target, env={"SUDO_USER": "assessor"}, euid=0, lookup=fake_user)
            self.assertGreaterEqual(changed, 3)
            self.assertEqual((target / "captures" / "s.pcap").stat().st_uid, 1000)


class RunDefaultsTests(unittest.TestCase):
    def test_port_and_data_dir_flags(self):
        import run
        self.assertEqual(run.DEFAULT_PORT, 8767)
        line = run.startup_lines("127.0.0.1", 8767, "abc")[0]
        self.assertIn(f"{edition.NAME} v", line)
        self.assertIn("http://localhost:8767/?token=abc", line)

    def test_demo_opens_from_the_data_folder_without_root(self):
        import argparse
        import http.client
        import threading
        import run
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(host="127.0.0.1", port=0, allowed_host=[], data_dir=tmp, demo=True)
            server, capture, data_dir = run.build_server(args)
            try:
                self.assertEqual(Path(server.store.path), Path(tmp).resolve() / "demo.db")
                self.assertTrue((Path(tmp) / "demo.db").is_file())
                threading.Thread(target=server.serve_forever, daemon=True).start()
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=20)
                conn.request("GET", "/api/status", headers={"X-Scout-Token": server.token})
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                import json
                status = json.loads(response.read())
                self.assertEqual(status["dataset"], "demo")
                self.assertGreater(status["assets"], 10)
            finally:
                server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
