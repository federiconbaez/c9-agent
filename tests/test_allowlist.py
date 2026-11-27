import os

import pytest

from c9agent import allowlist
from c9agent.errors import ActionNotAllowed, ArgumentError


def test_unknown_action(env):
    for action in ("shell", "exec", "bash", "Ping", "", "../ping"):
        with pytest.raises(ActionNotAllowed):
            allowlist.plan(env["cfg"], "j1", action, {})


def test_blender_script_argv_is_list(env):
    p = allowlist.plan(env["cfg"], "j1", "blender_script",
                       {"blend": "escena.blend", "script": "materiales.py"})
    assert p.argv[0] == "/bin/echo" and "--disable-autoexec" in p.argv
    assert isinstance(p.argv, list)


@pytest.mark.parametrize("bad", ["../secreto.blend", "/etc/passwd.blend", "a/../../secreto.blend",
                                 "./escena.blend", "escena.blend\x00.py", "", "..", "a//b.blend",
                                 "-oProxyCommand.blend", "escena.blend;id"])
def test_path_traversal_blend(env, bad):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "blender_render",
                       {"blend": bad, "frame_start": 1, "frame_end": 2})


def test_symlink_escape(env):
    link = env["cfg"].projects_root / "fuga.blend"
    os.symlink(env["root"] / "secreto.blend", link)
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "blender_render",
                       {"blend": "fuga.blend", "frame_start": 1, "frame_end": 1})


def test_script_must_come_from_scripts_root(env):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "unreal_python", {"script": "../proj/escena.blend"})


def test_wrong_extension(env):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "blender_script", {"blend": "escena.blend", "script": "x.sh"})


def test_extra_args_rejected(env):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "blender_render",
                       {"blend": "escena.blend", "frame_start": 1, "frame_end": 2, "python_expr": "x"})


@pytest.mark.parametrize("fs,fe", [(5, 1), (-1, 3), (1, 5000), (True, 2), ("1", 2)])
def test_frame_range(env, fs, fe):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "blender_render",
                       {"blend": "escena.blend", "frame_start": fs, "frame_end": fe})


def test_engine_not_allowed(env):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "j1", "blender_render",
                       {"blend": "escena.blend", "frame_start": 1, "frame_end": 1, "engine": "$(id)"})


def test_job_id_cannot_escape_output(env):
    with pytest.raises(ArgumentError):
        allowlist.plan(env["cfg"], "../../etc", "ping", {})
