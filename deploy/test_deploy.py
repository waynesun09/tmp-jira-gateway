"""deploy.sh post-check parsing, against fake gcloud and curl: python3 -m unittest discover -s deploy

Runs `deploy.sh --execute post` with a PATH whose gcloud and curl are stubs, so nothing
reaches GCP or the network. Needs bash and jq.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

FAKE_GCLOUD = r"""#!/bin/bash
# Fake gcloud: only `run services describe`.
for a in "$@"; do
  if [ "$a" = "--format=json" ]; then
    echo '{"status":{"latestCreatedRevisionName":"r1","latestReadyRevisionName":"r1","traffic":[{"revisionName":"r1","percent":100}]}}'
    exit 0
  fi
done
echo "https://gw.example"
"""

# Fake curl: writes the body chosen by FAKE_MODE to the -o file and prints the status.
FAKE_CURL = r"""#!/bin/bash
out="" auth="" url=""
while [ $# -gt 0 ]; do
  case "$1" in
  -o) out=$2; shift ;;
  -H) auth=$2; shift ;;
  -w|--connect-timeout|--max-time) shift ;;
  -*) ;;
  *) url=$1 ;;
  esac
  shift
done
case "$url" in
*/healthz) body='{"status":"ok"}' code=200 ;;
*)
  code=401
  case "$FAKE_MODE" in
  current) body='{"code":"unauthenticated","error":"unauthorized"}' ;;
  reordered) body='{"error":"unauthorized","code":"unauthenticated","extra":1}' ;;
  stale) body='{"error":"unauthorized"}' ;;
  wrongcode) body='{"code":"not_granted","error":"not granted"}' ;;
  html) body='<html>401</html>' ;;
  esac
  ;;
esac
printf '%s' "$body" >"$out"
printf '%s' "$code"
"""


@unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "needs bash and jq")
class PostCheckTest(unittest.TestCase):
    def setUp(self):
        self.bin = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.bin)
        for name, text in (("gcloud", FAKE_GCLOUD), ("curl", FAKE_CURL)):
            p = self.bin / name
            p.write_text(text)
            p.chmod(p.stat().st_mode | stat.S_IXUSR)

    def post(self, mode):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FAKE_MODE=mode)
        return subprocess.run(
            ["bash", str(HERE / "deploy.sh"), "--execute", "post"],
            env=env, capture_output=True, text=True, timeout=60,
        )

    def test_current_body_passes(self):
        r = self.post("current")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok   no token: 401", r.stdout)
        self.assertIn("ok   revision r1 ready", r.stdout)

    def test_field_order_and_extra_fields_pass(self):
        r = self.post("reordered")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_bad_bodies_fail(self):
        for mode in ("stale", "wrongcode", "html"):
            with self.subTest(mode):
                r = self.post(mode)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("FAIL no token", r.stderr)


if __name__ == "__main__":
    unittest.main()
