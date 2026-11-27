import time

import pytest

from c9agent import verify
from c9agent.errors import JobFormatError, ReplayError, SignatureError
from conftest import make_job, sign


def test_valid_job(tmp_path, keys, env):
    jp, sp = sign(make_job(), keys["good"], tmp_path)
    job = verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])
    assert job.signer == "federico@cortex9" and job.action == "ping"


def test_unknown_key_rejected(tmp_path, keys, env):
    jp, sp = sign(make_job(), keys["evil"], tmp_path)
    with pytest.raises(SignatureError):
        verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])


def test_tampered_payload_rejected(tmp_path, keys, env):
    jp, sp = sign(make_job(), keys["good"], tmp_path)
    tampered = jp.read_bytes().replace(b'"ping"', b'"blender_render"')
    with pytest.raises(SignatureError):
        verify.verify_job(tampered, sp, keys["allowed"], env["nonces"])


def test_missing_signature(tmp_path, keys, env):
    with pytest.raises(SignatureError):
        verify.verify_job(make_job(), tmp_path / "nada.sig", keys["allowed"], env["nonces"])


def test_garbage_signature(tmp_path, keys, env):
    sp = tmp_path / "x.sig"
    sp.write_text("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")
    with pytest.raises(SignatureError):
        verify.verify_job(make_job(), sp, keys["allowed"], env["nonces"])


def test_wrong_namespace_rejected(tmp_path, keys, env):
    jp, sp = sign(make_job(), keys["good"], tmp_path, namespace="git")
    with pytest.raises(SignatureError):
        verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])


def test_replay_same_nonce(tmp_path, keys, env):
    jp, sp = sign(make_job(), keys["good"], tmp_path)
    payload = jp.read_bytes()
    verify.verify_job(payload, sp, keys["allowed"], env["nonces"])
    with pytest.raises(ReplayError):
        verify.verify_job(payload, sp, keys["allowed"], env["nonces"])


def test_expired(tmp_path, keys, env):
    jp, sp = sign(make_job(issued=int(time.time()) - 1000, ttl=500), keys["good"], tmp_path)
    with pytest.raises(ReplayError):
        verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])


def test_future_issued(tmp_path, keys, env):
    jp, sp = sign(make_job(issued=int(time.time()) + 3600), keys["good"], tmp_path)
    with pytest.raises(ReplayError):
        verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])


def test_lifetime_too_long(tmp_path, keys, env):
    jp, sp = sign(make_job(ttl=verify.MAX_LIFETIME_S + 1), keys["good"], tmp_path)
    with pytest.raises(ReplayError):
        verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])


def test_extra_field_rejected(tmp_path, keys, env):
    jp, sp = sign(make_job(shell="rm -rf /"), keys["good"], tmp_path)
    with pytest.raises(JobFormatError):
        verify.verify_job(jp.read_bytes(), sp, keys["allowed"], env["nonces"])


def test_nonce_not_consumed_when_signature_fails(tmp_path, keys, env):
    payload = make_job(nonce="A" * 32)
    jp, sp = sign(payload, keys["evil"], tmp_path)
    with pytest.raises(SignatureError):
        verify.verify_job(payload, sp, keys["allowed"], env["nonces"])
    assert not (env["nonces"].root / ("A" * 32)).exists()


def test_prune_only_expired(env):
    store = env["nonces"]
    (store.root / ("o" * 20)).write_text(str(int(time.time()) - 10_000))
    (store.root / ("n" * 20)).write_text(str(int(time.time()) + 10_000))
    assert store.prune() == 1
    assert (store.root / ("n" * 20)).exists()
