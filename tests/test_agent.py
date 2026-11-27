import json
import sys

from c9agent import agent, runner
from c9agent.allowlist import Plan
from conftest import make_job, sign


def _run(env, keys, payload, key="good", name="job-1"):
    sign(payload, keys[key], env["queue"].root / "incoming", name=name)
    for jp in env["queue"].pending():
        agent.process_one(jp, env["queue"], env["cfg"], keys["allowed"], env["nonces"], None, {})
    return json.loads((env["queue"].root / "results" / f"{name}.result.json").read_text())


def test_end_to_end_ok(env, keys):
    res = _run(env, keys, make_job(action="blender_script",
                                   args={"blend": "escena.blend", "script": "materiales.py"}))
    assert res["status"] == "ok" and res["signer"] == "federico@cortex9"
    assert (env["queue"].root / "done" / "job-1.json").exists()


def test_unsigned_injection_never_runs(env, keys, tmp_path):
    marker = tmp_path / "pwned"
    inc = env["queue"].root / "incoming"
    (inc / "job-1.json").write_bytes(make_job(action="blender_script",
                                              args={"blend": "escena.blend", "script": "materiales.py"}))
    for jp in env["queue"].pending():
        agent.process_one(jp, env["queue"], env["cfg"], keys["allowed"], env["nonces"], None, {})
    res = json.loads((env["queue"].root / "results" / "job-1.result.json").read_text())
    assert res["status"] == "rejected" and res["reason"] == "SignatureError"
    assert not marker.exists()
    assert (env["queue"].root / "failed" / "job-1.json").exists()


def test_disallowed_action_rejected(env, keys):
    res = _run(env, keys, make_job(action="shell", args={"cmd": "id"}))
    assert res["status"] == "rejected" and res["reason"] == "ActionNotAllowed"


def test_replay_via_queue(env, keys):
    payload = make_job()
    assert _run(env, keys, payload)["status"] == "ok"
    assert _run(env, keys, payload, name="job-1b")["reason"] == "ReplayError"


def test_runner_timeout(tmp_path):
    p = Plan("t", [sys.executable, "-c", "import time; time.sleep(30)"], 1, tmp_path / "o")
    r = runner.run(p)
    assert r.timed_out


def test_runner_no_shell(tmp_path):
    p = Plan("t", ["/bin/echo", "$(id)", ";", "whoami"], 5, tmp_path / "o")
    r = runner.run(p)
    assert r.stdout_tail.strip() == "$(id) ; whoami"


def test_runner_minimal_env(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "secreto")
    p = Plan("t", [sys.executable, "-c", "import os; print(sorted(os.environ))"], 5, tmp_path / "o")
    r = runner.run(p)
    assert "GH_TOKEN" not in r.stdout_tail
