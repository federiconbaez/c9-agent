"""Herramienta del emisor: arma un trabajo con nonce y vencimiento y lo firma.

Uso: python -m c9agent.sign_job --key ~/.ssh/id_ed25519_sk --action ping --args '{}' --out cola/incoming
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import time
from pathlib import Path

from .verify import JOB_NAMESPACE


def build(job_id: str, action: str, args: dict, ttl: int = 3600) -> bytes:
    now = int(time.time())
    job = {"version": 1, "id": job_id, "nonce": secrets.token_urlsafe(24), "issued_at": now,
           "expires_at": now + ttl, "action": action, "args": args}
    return json.dumps(job, sort_keys=True).encode()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--id", default=None)
    ap.add_argument("--action", required=True)
    ap.add_argument("--args", default="{}")
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    job_id = a.id or f"job-{int(time.time())}-{secrets.token_hex(3)}"
    path = a.out / f"{job_id}.json"
    tmp = a.out / f".{job_id}.json.tmp"
    tmp.write_bytes(build(job_id, a.action, json.loads(a.args), a.ttl))
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", a.key, "-n", JOB_NAMESPACE, str(tmp)],
                   check=True)
    # la firma primero, luego el trabajo: el agente nunca ve un .json sin .sig
    Path(str(tmp) + ".sig").rename(str(path) + ".sig")
    tmp.rename(path)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
