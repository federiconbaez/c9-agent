"""Backend de cola basado en directorios (sirve también sobre un clon git).

Estructura:
  incoming/<id>.json + <id>.json.sig   trabajos firmados (escritos por el emisor)
  processing/                          reclamados con rename atómico
  done/ failed/                        archivados
  results/<id>.result.json(.sig)       resultados firmados por el agente
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

SUBDIRS = ("incoming", "processing", "done", "failed", "results")


class DirQueue:
    def __init__(self, root: Path):
        self.root = root
        for d in SUBDIRS:
            (root / d).mkdir(parents=True, exist_ok=True, mode=0o750)

    def pending(self) -> Iterator[Path]:
        for p in sorted((self.root / "incoming").iterdir()):
            if p.suffix == ".json" and p.is_file() and not p.is_symlink():
                yield p

    def claim(self, job_path: Path) -> tuple[Path, Path] | None:
        """Mueve trabajo + firma a processing/. None si otro proceso lo tomó."""
        dst = self.root / "processing" / job_path.name
        sig = job_path.with_name(job_path.name + ".sig")
        try:
            os.rename(job_path, dst)
        except FileNotFoundError:
            return None
        dst_sig = dst.with_name(dst.name + ".sig")
        try:
            os.rename(sig, dst_sig)
        except FileNotFoundError:
            pass  # sin firma: la verificación lo rechazará
        return dst, dst_sig

    def finish(self, job_path: Path, ok: bool) -> None:
        target = self.root / ("done" if ok else "failed")
        for p in (job_path, job_path.with_name(job_path.name + ".sig")):
            if p.exists():
                os.replace(p, target / p.name)

    def write_result(self, name: str, result: dict) -> Path:
        path = self.root / "results" / f"{name}.result.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        os.replace(tmp, path)
        return path
