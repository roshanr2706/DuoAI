import re

from duo_agent.cli import main
from duo_agent.store import SecretStore

RFC = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_code_prints_six_digits(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "cfg"
    SecretStore(cfg).save({"hotp_secret": RFC, "counter": 0})
    monkeypatch.setenv("DUO_AGENT_HOME", str(cfg))
    rc = main(["code"])
    out = capsys.readouterr().out
    assert rc == 0
    assert re.fullmatch(r"\d{6}\n", out), repr(out)


def test_code_without_store_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DUO_AGENT_HOME", str(tmp_path / "empty"))
    rc = main(["code"])
    captured = capsys.readouterr()
    assert rc != 0
    assert captured.err.strip(), "expected an error message on stderr"


def test_enroll_subcommand_invokes_enroll(tmp_path, monkeypatch):
    monkeypatch.setenv("DUO_AGENT_HOME", str(tmp_path / "cfg"))
    called = {}

    def fake_enroll(activation, store):
        called["activation"] = activation

    monkeypatch.setattr("duo_agent.enroll.enroll", fake_enroll)
    rc = main(["enroll", "CODE-aGVsbG8="])
    assert rc == 0
    assert called["activation"] == "CODE-aGVsbG8="
