"""Bucle principal: reclamar -> verificar -> planificar -> ejecutar -> resultado firmado."""

from __future__ import annotations

import argparse
import hashlib
import logging
import re
import shutil
import subprocess
import time
import tomllib
from pathlib import Path

from . import allowlist, runner, verify
from .errors import AgentError
from .queue_dir import DirQueue

log = logging.getLogger("c9agent")
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _result_name(job_path: Path) -> str:
    stem = job_path.stem
    return stem if _SAFE.match(stem) else "invalid-" + hashlib.sha256(stem.encode()).hexdigest()[:16]


def _c9mem(cfg: dict, task: str, phase: str) -> None:
    """Integración opcional con c9mem: si no está instalado o falla, no bloquea."""
    exe = cfg.get("c9mem_bin")
    if not exe or not shutil.which(exe):
        return
    try:
        subprocess.run([exe, "--agent", cfg.get("c9mem_agent", "c9-agent"), "event-append",
                        f"c9agent.{phase}", "--task", task], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        log.warning("c9mem no disponible")


def process_one(job_path: Path, q: DirQueue, acfg: allowlist.Config, allowed: Path,
                nonces: verify.NonceStore, result_key: Path | None, extra: dict) -> dict:
    name = _result_name(job_path)
    claimed = q.claim(job_path)
    if claimed is None:
        return {}
    jp, sp = claimed
    result: dict = {"job_file": name, "received_at": int(time.time())}
    ok = False
    try:
        payload = jp.read_bytes()
        job = verify.verify_job(payload, sp, allowed, nonces)
        result.update(id=job.id, signer=job.signer, action=job.action,
                      job_sha256=hashlib.sha256(payload).hexdigest())
        plan = allowlist.plan(acfg, job.id, job.action, job.args)
        _c9mem(extra, job.id, "start")
        rr = runner.run(plan)
        _c9mem(extra, job.id, "end")
        ok = rr.returncode == 0 and not rr.timed_out
        result.update(status="ok" if ok else "error", returncode=rr.returncode,
                      timed_out=rr.timed_out, duration_s=rr.duration_s,
                      stdout_tail=rr.stdout_tail, stderr_tail=rr.stderr_tail,
                      output_dir=str(plan.output_dir))
    except AgentError as exc:
        result.update(status="rejected", reason=type(exc).__name__, detail=str(exc))
    q.finish(jp, ok)
    path = q.write_result(name, result)
    if result_key:
        verify.sign_file(path, result_key)
    log.info("%s -> %s", name, result.get("status"))
    return result


def load_config(path: Path) -> tuple[DirQueue, allowlist.Config, Path, verify.NonceStore, Path | None, dict]:
    raw = tomllib.loads(path.read_text())
    q = DirQueue(Path(raw["queue_dir"]))
    acfg = allowlist.Config(Path(raw["projects_root"]), Path(raw["scripts_root"]),
                            Path(raw["output_root"]), raw.get("blender_bin", "blender"),
                            raw.get("unreal_client", "c9-unreal-exec"))
    key = Path(raw["result_key"]) if raw.get("result_key") else None
    return (q, acfg, Path(raw["allowed_signers"]), verify.NonceStore(Path(raw["state_dir"]) / "nonces"),
            key, raw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="c9-agent")
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--once", action="store_true", help="procesar la cola una vez y salir")
    ap.add_argument("--interval", type=float, default=10.0)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    q, acfg, allowed, nonces, key, extra = load_config(a.config)
    while True:
        nonces.prune()
        for job in q.pending():
            process_one(job, q, acfg, allowed, nonces, key, extra)
        if a.once:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    raise SystemExit(main())
