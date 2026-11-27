import json
import secrets
import subprocess
import time
from pathlib import Path

import pytest

from c9agent import allowlist, verify
from c9agent.queue_dir import DirQueue


def _keygen(path: Path) -> str:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(path)], check=True)
    return Path(str(path) + ".pub").read_text().strip()


@pytest.fixture
def keys(tmp_path):
    good = tmp_path / "k_good"
    evil = tmp_path / "k_evil"
    pub = _keygen(good)
    _keygen(evil)
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f'federico@cortex9 namespaces="{verify.JOB_NAMESPACE}" {pub}\n')
    return {"good": good, "evil": evil, "allowed": allowed}


def make_job(action="ping", args=None, job_id="job-1", ttl=600, issued=None, nonce=None, **override):
    now = int(time.time()) if issued is None else issued
    job = {"version": 1, "id": job_id, "nonce": nonce or secrets.token_urlsafe(24),
           "issued_at": now, "expires_at": now + ttl, "action": action, "args": args or {}}
    job.update(override)
    return json.dumps(job, sort_keys=True).encode()


def sign(payload: bytes, key: Path, where: Path, name="job-1", namespace=verify.JOB_NAMESPACE):
    jp = where / f"{name}.json"
    jp.write_bytes(payload)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", namespace, str(jp)], check=True)
    return jp, Path(str(jp) + ".sig")


@pytest.fixture
def env(tmp_path):
    proj = tmp_path / "proj"; scripts = tmp_path / "scripts"; out = tmp_path / "out"
    for d in (proj, scripts, out):
        d.mkdir()
    (proj / "escena.blend").write_bytes(b"BLENDER")
    (scripts / "materiales.py").write_text("print('ok')\n")
    (tmp_path / "secreto.blend").write_bytes(b"x")
    cfg = allowlist.Config(proj, scripts, out, blender_bin="/bin/echo", unreal_client="/bin/echo")
    return {"cfg": cfg, "queue": DirQueue(tmp_path / "queue"),
            "nonces": verify.NonceStore(tmp_path / "state" / "nonces"), "root": tmp_path}
