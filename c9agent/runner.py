"""Ejecución sin shell, con entorno mínimo, timeout y límites de recursos."""

from __future__ import annotations

import os
import resource
import subprocess
import time
from dataclasses import dataclass

from .allowlist import Plan

MAX_LOG_BYTES = 256 * 1024
DEFAULT_LIMITS = {
    resource.RLIMIT_NOFILE: 1024,
    resource.RLIMIT_CORE: 0,
    resource.RLIMIT_FSIZE: 20 * 1024**3,
}


@dataclass
class RunResult:
    returncode: int
    timed_out: bool
    duration_s: float
    stdout_tail: str
    stderr_tail: str


def _tail(data: bytes) -> str:
    return data[-MAX_LOG_BYTES:].decode("utf-8", "replace")


def _limits(limits: dict):
    def apply() -> None:
        os.setsid()
        for res, value in limits.items():
            resource.setrlimit(res, (value, value))
    return apply


def run(plan: Plan, limits: dict | None = None) -> RunResult:
    plan.output_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8",
           "HOME": str(plan.output_dir), **plan.env}
    start = time.monotonic()
    proc = subprocess.Popen(plan.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=plan.output_dir, env=env,
                            preexec_fn=_limits(limits or DEFAULT_LIMITS), shell=False)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=plan.timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, 9)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    return RunResult(proc.returncode, timed_out, round(time.monotonic() - start, 3),
                     _tail(out), _tail(err))
