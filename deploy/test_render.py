"""Rejection paths of render.py: python3 -m unittest discover -s deploy"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import render

SRC = Path(__file__).resolve().parent


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        for f in ("gateway.env", "config.tmpl.json", "grants.example.json"):
            shutil.copy(SRC / f, self.dir / f)
        self.addCleanup(shutil.rmtree, self.dir)
        patcher = mock.patch.object(render, "HERE", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.grants = self.dir / "grants.example.json"

    def write_grants(self, value):
        self.grants.write_text(value if isinstance(value, str) else json.dumps(value))

    def good(self):
        return json.loads((SRC / "grants.example.json").read_text())

    def test_example_renders(self):
        cfg = json.loads(render.render(self.grants))
        self.assertEqual(cfg["audience"], "fullsend-jira-gateway-dev")
        self.assertEqual(len(cfg["grants"]), 2)
        self.assertTrue(cfg["read_client_secret_file"].startswith("/etc/jira-gateway/"))

    def test_rejections(self):
        g = self.good()
        cases = {
            "numeric id": [dict(g[0], repository_id=1)],
            "extra key": [dict(g[0], ref="main")],
            "bad level": [dict(g[0], level="admin")],
            "lowercase project": [dict(g[0], projects=["abc"])],
            "empty projects": [dict(g[0], projects=[])],
            "bad repo": [dict(g[0], repository='x"] || true')],
            "duplicate": [g[0], g[0]],
            "empty": [],
        }
        for name, grants in cases.items():
            with self.subTest(name):
                self.write_grants(grants)
                with self.assertRaises(ValueError):
                    render.render(self.grants)

    def test_duplicate_json_key(self):
        self.write_grants('[{"repository":"a/b","repository":"c/d"}]')
        with self.assertRaises(ValueError):
            render.render(self.grants)

    def test_env_shell_value(self):
        env = (self.dir / "gateway.env").read_text().replace("R=us-central1", "R=$(id)")
        (self.dir / "gateway.env").write_text(env)
        with self.assertRaises(ValueError):
            render.load_env()

    def test_env_name_prefix(self):
        env = (self.dir / "gateway.env").read_text().replace(
            "N=fullsend-jira-gateway-dev", "N=fullsend-inference-gateway"
        )
        (self.dir / "gateway.env").write_text(env)
        with self.assertRaises(ValueError):
            render.load_env()


if __name__ == "__main__":
    unittest.main()
