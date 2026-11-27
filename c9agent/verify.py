"""Verificación de firmas SSH (ssh-keygen -Y) y anti-replay.

Compatible con claves ed25519 y sk-ssh-ed25519@openssh.com (YubiKey).
La identidad del firmante se obtiene con `find-principals` contra el
archivo allowed_signers; nunca se toma del contenido del trabajo.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import JobFormatError, ReplayError, SignatureError

JOB_NAMESPACE = "c9-agent-job"
RESULT_NAMESPACE = "c9-agent-result"

MAX_JOB_BYTES = 64 * 1024
MAX_LIFETIME_S = 24 * 3600
CLOCK_SKEW_S = 120

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_REQUIRED = {"version", "id", "nonce", "issued_at", "expires_at", "action", "args"}


@dataclass(frozen=True)
class Job:
    id: str
    nonce: str
    issued_at: int
    expires_at: int
    action: str
    args: dict
    signer: str


def _ssh_keygen(args: list[str], data: bytes, timeout: float = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh-keygen", *args],
        input=data,
        capture_output=True,
        timeout=timeout,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )


def verify_signature(payload: bytes, sig_path: Path, allowed_signers: Path,
                     namespace: str = JOB_NAMESPACE) -> str:
    """Devuelve el principal que firmó `payload` o lanza SignatureError."""
    if not sig_path.is_file():
        raise SignatureError("firma ausente")
    if not allowed_signers.is_file():
        raise SignatureError("allowed_signers ausente")
    found = _ssh_keygen(["-Y", "find-principals", "-f", str(allowed_signers),
                         "-s", str(sig_path)], b"")
    principals = [p for p in found.stdout.decode("utf-8", "replace").split() if p]
    if found.returncode != 0 or len(principals) != 1:
        raise SignatureError("firmante desconocido")
    principal = principals[0]
    res = _ssh_keygen(["-Y", "verify", "-f", str(allowed_signers), "-I", principal,
                       "-n", namespace, "-s", str(sig_path)], payload)
    if res.returncode != 0:
        raise SignatureError("firma inválida")
    return principal


def parse_job(payload: bytes, signer: str, now: float | None = None) -> Job:
    if len(payload) > MAX_JOB_BYTES:
        raise JobFormatError("trabajo demasiado grande")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JobFormatError("JSON inválido") from exc
    if not isinstance(data, dict) or set(data) != _REQUIRED:
        raise JobFormatError("campos inválidos")
    if data["version"] != 1:
        raise JobFormatError("versión no soportada")
    if not isinstance(data["id"], str) or not _ID_RE.match(data["id"]):
        raise JobFormatError("id inválido")
    if not isinstance(data["nonce"], str) or not _NONCE_RE.match(data["nonce"]):
        raise JobFormatError("nonce inválido")
    for k in ("issued_at", "expires_at"):
        if not isinstance(data[k], int) or isinstance(data[k], bool):
            raise JobFormatError(f"{k} inválido")
    if not isinstance(data["action"], str) or not isinstance(data["args"], dict):
        raise JobFormatError("acción o argumentos inválidos")
    now = time.time() if now is None else now
    if data["issued_at"] > now + CLOCK_SKEW_S:
        raise ReplayError("emitido en el futuro")
    if data["expires_at"] <= now:
        raise ReplayError("trabajo vencido")
    if data["expires_at"] - data["issued_at"] > MAX_LIFETIME_S:
        raise ReplayError("vigencia demasiado larga")
    return Job(data["id"], data["nonce"], data["issued_at"], data["expires_at"],
               data["action"], data["args"], signer)


class NonceStore:
    """Registro de nonces usados: un archivo por nonce, creado con O_EXCL."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def consume(self, job: Job) -> None:
        path = self.root / job.nonce
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ReplayError("nonce repetido") from exc
        with os.fdopen(fd, "w") as fh:
            fh.write(str(job.expires_at))

    def prune(self, now: float | None = None) -> int:
        """Borra nonces cuyo trabajo ya venció (no se pueden reutilizar igual)."""
        now = time.time() if now is None else now
        removed = 0
        for p in self.root.iterdir():
            try:
                if int(p.read_text().strip()) + CLOCK_SKEW_S < now:
                    p.unlink()
                    removed += 1
            except (ValueError, OSError):
                continue
        return removed


def verify_job(payload: bytes, sig_path: Path, allowed_signers: Path,
               nonces: NonceStore, now: float | None = None) -> Job:
    """Orden fijo: firma -> formato -> vigencia -> nonce. Nada se ejecuta sin pasar todo."""
    signer = verify_signature(payload, sig_path, allowed_signers, JOB_NAMESPACE)
    job = parse_job(payload, signer, now)
    nonces.consume(job)
    return job


def sign_file(path: Path, key: Path, namespace: str = RESULT_NAMESPACE) -> Path:
    """Firma un archivo (resultados) con la clave del agente. Devuelve la ruta .sig."""
    res = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", namespace,
                          str(path)], capture_output=True, timeout=30)
    if res.returncode != 0:
        raise SignatureError("no se pudo firmar el resultado")
    return path.with_name(path.name + ".sig")
