#!/usr/bin/env python3
"""Render deploy/out/config.json from config.tmpl.json, gateway.env and a grants file.

render.py [--grants FILE]               write deploy/out/config.json (default grants: deploy/grants.json)
render.py [--grants FILE] --verify-ids  also check every grant's ids against the GitHub API (needs gh)
render.py --print-env                   print the validated gateway.env as shell assignments (deploy.sh)

Standard library only. The gateway re-validates the rendered file (`jira-gateway -check`).
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENV_KEYS = (
    "P",
    "R",
    "N",
    "AUD",
    "ISSUER",
    "CONFIG_SECRET",
    "READ_ID_SECRET",
    "READ_SECRET_SECRET",
    "WRITE_ID_SECRET",
    "WRITE_SECRET_SECRET",
    "MIN_INSTANCES",
    "MAX_INSTANCES",
    "CONCURRENCY",
    "CPU",
    "MEMORY",
    "MAX_RESPONSE_BYTES",
)
INT_KEYS = ("MAX_INSTANCES", "CONCURRENCY", "CPU", "MAX_RESPONSE_BYTES")
# The only GCP project this deploy may target.
DEV_PROJECT = "example-dev-project"
# Per-request memory: the response buffer, its decoded tree and the re-encoded copy.
COPIES_PER_RESPONSE = 4
MEMORY_HEADROOM = 128 << 20
MEMORY_RE = re.compile(r"^([0-9]+)(Mi|Gi)$")
# deploy.sh evals the --print-env output: keep values to shell-inert characters.
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/-]+$")
REPO = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
DIGITS = re.compile(r"^[0-9]{1,20}$")
CLOUD_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
PROJECT = re.compile(r"^[A-Z][A-Z0-9_]+$")
GRANT_KEYS = {"repository", "repository_id", "repository_owner_id", "cloudId", "level", "projects"}


def load_env() -> dict:
    """Plain KEY=VALUE lines; no quoting, no inline comments, no duplicates."""
    env = {}
    for n, line in enumerate((HERE / "gateway.env").read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in ENV_KEYS or not SAFE_VALUE.match(value):
            raise ValueError(f"gateway.env:{n}: expected KEY=VALUE with KEY in {ENV_KEYS} and a plain value")
        if key in env:
            raise ValueError(f"gateway.env:{n}: duplicate {key}")
        env[key] = value
    missing = [k for k in ENV_KEYS if k not in env]
    if missing:
        raise ValueError(f"gateway.env: missing {missing}")
    for k in INT_KEYS:
        if not env[k].isdigit() or int(env[k]) < 1:
            raise ValueError(f"gateway.env: {k} must be a positive integer")
    if not env["N"].startswith("fullsend-jira-gateway-dev"):
        raise ValueError("gateway.env: N must start with fullsend-jira-gateway-dev")
    if env["P"] != DEV_PROJECT:
        raise ValueError(f"gateway.env: P must be {DEV_PROJECT}")
    if not env["MIN_INSTANCES"].isdigit() or int(env["MIN_INSTANCES"]) > int(env["MAX_INSTANCES"]):
        raise ValueError("gateway.env: MIN_INSTANCES must be an integer between 0 and MAX_INSTANCES")
    m = MEMORY_RE.match(env["MEMORY"])
    if not m:
        raise ValueError("gateway.env: MEMORY must look like 512Mi or 1Gi")
    memory = int(m.group(1)) << (20 if m.group(2) == "Mi" else 30)
    need = COPIES_PER_RESPONSE * int(env["CONCURRENCY"]) * int(env["MAX_RESPONSE_BYTES"]) + MEMORY_HEADROOM
    if need > memory:
        raise ValueError(
            f"gateway.env: {COPIES_PER_RESPONSE} x CONCURRENCY x MAX_RESPONSE_BYTES + 128 MiB = "
            f"{need >> 20} MiB exceeds MEMORY {env['MEMORY']}; lower CONCURRENCY or MAX_RESPONSE_BYTES"
        )
    return env


def no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def load_grants(path: Path) -> list:
    grants = json.loads(path.read_text(), object_pairs_hook=no_duplicates)
    if not isinstance(grants, list) or not grants:
        raise ValueError(f"{path.name}: expected a non-empty JSON list of grants")
    repos, ids = set(), set()
    for g in grants:
        if not isinstance(g, dict) or set(g) != GRANT_KEYS:
            raise ValueError(f"{path.name}: each grant needs exactly {sorted(GRANT_KEYS)}: {g!r}")
        if not isinstance(g["repository"], str) or not REPO.match(g["repository"]):
            raise ValueError(f"{path.name}: {g['repository']!r} is not owner/name")
        for k in ("repository_id", "repository_owner_id"):
            if not isinstance(g[k], str) or not DIGITS.match(g[k]):
                raise ValueError(f"{path.name}: {g['repository']}: {k} must be a quoted digit string")
        if not isinstance(g["cloudId"], str) or not CLOUD_ID.match(g["cloudId"]):
            raise ValueError(f"{path.name}: {g['repository']}: cloudId is not a cloud id")
        if g["level"] not in ("read", "write"):
            raise ValueError(f"{path.name}: {g['repository']}: level must be read or write")
        projects = g["projects"]
        if not isinstance(projects, list) or not projects or not all(isinstance(p, str) and PROJECT.match(p) for p in projects):
            raise ValueError(f"{path.name}: {g['repository']}: projects must be a non-empty list of project keys")
        if g["repository"] in repos or g["repository_id"] in ids:
            raise ValueError(f"{path.name}: duplicate grant for {g['repository']}")
        repos.add(g["repository"])
        ids.add(g["repository_id"])
    return grants


def render(grants_path: Path) -> str:
    env = load_env()
    cfg = json.loads((HERE / "config.tmpl.json").read_text(), object_pairs_hook=no_duplicates)
    cfg["issuer"] = env["ISSUER"]
    cfg["audience"] = env["AUD"]
    cfg["max_response_bytes"] = int(env["MAX_RESPONSE_BYTES"])
    cfg["grants"] = load_grants(grants_path)
    return json.dumps(cfg, indent=2, sort_keys=True) + "\n"


def verify_ids(grants_path: Path) -> None:
    bad = 0
    for g in load_grants(grants_path):
        try:
            out = subprocess.run(
                ["gh", "api", f"repos/{g['repository']}", "--jq",
                 "{full_name, id: (.id|tostring), owner_id: (.owner.id|tostring)}"],
                check=True, capture_output=True, text=True,
            ).stdout
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            sys.exit(f"--verify-ids: gh api repos/{g['repository']} failed: {e}")
        got = json.loads(out)
        want = {"full_name": g["repository"], "id": g["repository_id"], "owner_id": g["repository_owner_id"]}
        if got != want:
            print(f"MISMATCH {g['repository']}: grants {want} != GitHub {got}")
            bad += 1
    if bad:
        sys.exit(1)
    print("all grant ids match GitHub")


def main(argv: list) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--grants", default=str(HERE / "grants.json"))
    ap.add_argument("--verify-ids", action="store_true")
    ap.add_argument("--print-env", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.print_env:
            for k, v in load_env().items():
                print(f"{k}={v}")
            return
        grants = Path(args.grants)
        if args.verify_ids:
            verify_ids(grants)
        text = render(grants)
    except (ValueError, KeyError, TypeError, OSError) as e:
        sys.exit(str(e))
    out = HERE / "out"
    out.mkdir(exist_ok=True)
    (out / "config.json").write_text(text)
    print(f"wrote {out / 'config.json'}")


if __name__ == "__main__":
    main(sys.argv[1:])
