"""Allowlist estricta de acciones. Cada acción valida sus argumentos y
produce un argv fijo (lista), nunca una cadena de shell.

Las rutas son siempre relativas a raíces configuradas y se resuelven
para impedir path traversal y escapes por enlaces simbólicos.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .errors import ActionNotAllowed, ArgumentError

_REL_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
MAX_FRAMES = 1000


@dataclass(frozen=True)
class Config:
    projects_root: Path          # .blend / .uproject legibles por el agente
    scripts_root: Path           # scripts bpy / Unreal revisados (solo lectura)
    output_root: Path            # única ruta escribible
    blender_bin: str = "blender"
    unreal_client: str = "c9-unreal-exec"  # cliente Remote Execution (ver DISENO.md)


@dataclass(frozen=True)
class Plan:
    action: str
    argv: list[str]
    timeout_s: int
    output_dir: Path
    env: dict = field(default_factory=dict)


def safe_relpath(root: Path, rel: object, suffixes: tuple[str, ...] = (), must_exist: bool = True) -> Path:
    if not isinstance(rel, str) or not _REL_RE.match(rel):
        raise ArgumentError("ruta inválida")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ArgumentError("ruta inválida")
    if suffixes and not rel.endswith(suffixes):
        raise ArgumentError("extensión no permitida")
    root_r = root.resolve(strict=True)
    target = (root_r / rel).resolve(strict=must_exist)
    if target != root_r and root_r not in target.parents:
        raise ArgumentError("ruta fuera de la raíz")
    return target


def _name(value: object) -> str:
    if not isinstance(value, str) or not _NAME_RE.match(value):
        raise ArgumentError("nombre inválido")
    return value


def _int(value: object, lo: int, hi: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise ArgumentError("entero fuera de rango")
    return value


def _check_keys(args: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    keys = set(args)
    if not required <= keys or not keys <= required | optional:
        raise ArgumentError("argumentos inesperados o faltantes")


def _out_dir(cfg: Config, job_id: str) -> Path:
    return cfg.output_root.resolve() / _name(job_id)


def plan_ping(cfg: Config, job_id: str, args: dict) -> Plan:
    _check_keys(args, set())
    return Plan("ping", ["true"], 10, _out_dir(cfg, job_id))


def plan_blender_script(cfg: Config, job_id: str, args: dict) -> Plan:
    _check_keys(args, {"blend", "script"})
    blend = safe_relpath(cfg.projects_root, args["blend"], (".blend",))
    script = safe_relpath(cfg.scripts_root, args["script"], (".py",))
    out = _out_dir(cfg, job_id)
    argv = [cfg.blender_bin, "--background", "--factory-startup", "--disable-autoexec",
            str(blend), "--python", str(script), "--", "--output-dir", str(out)]
    return Plan("blender_script", argv, 1800, out)


def plan_blender_render(cfg: Config, job_id: str, args: dict) -> Plan:
    _check_keys(args, {"blend", "frame_start", "frame_end"}, {"engine"})
    blend = safe_relpath(cfg.projects_root, args["blend"], (".blend",))
    fs = _int(args["frame_start"], 0, 1_000_000)
    fe = _int(args["frame_end"], fs, fs + MAX_FRAMES - 1)
    engine = args.get("engine", "CYCLES")
    if engine not in ("CYCLES", "BLENDER_EEVEE_NEXT", "BLENDER_WORKBENCH"):
        raise ArgumentError("motor no permitido")
    out = _out_dir(cfg, job_id)
    argv = [cfg.blender_bin, "--background", "--factory-startup", "--disable-autoexec",
            str(blend), "--engine", engine, "--render-output", str(out / "frame_####"),
            "--frame-start", str(fs), "--frame-end", str(fe), "--render-anim"]
    return Plan("blender_render", argv, 4 * 3600, out)


def plan_unreal_python(cfg: Config, job_id: str, args: dict) -> Plan:
    _check_keys(args, {"script"})
    script = safe_relpath(cfg.scripts_root, args["script"], (".py",))
    out = _out_dir(cfg, job_id)
    argv = [cfg.unreal_client, "--script", str(script), "--output-dir", str(out)]
    return Plan("unreal_python", argv, 900, out)


ACTIONS: dict[str, Callable[[Config, str, dict], Plan]] = {
    "ping": plan_ping,
    "blender_script": plan_blender_script,
    "blender_render": plan_blender_render,
    "unreal_python": plan_unreal_python,
}


def plan(cfg: Config, job_id: str, action: str, args: dict) -> Plan:
    builder = ACTIONS.get(action)
    if builder is None:
        raise ActionNotAllowed("acción no permitida")
    return builder(cfg, job_id, args)
