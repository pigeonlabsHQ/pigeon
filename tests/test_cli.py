import json
import subprocess
import sys
from pathlib import Path

from pigeon.cli import main
from pigeon import grant

NOW = "2026-09-06T12:00:00Z"


def test_keygen_stdout(capsys):
    assert main(["keygen"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "public_key" in data
    assert "private_key" in data


def test_inspect(tmp_path, capsys):
    auth = grant(
        "agent:deploy",
        ["deploy"],
        ["environment:staging"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    path = tmp_path / "pass.json"
    path.write_bytes(auth.to_json_bytes())
    assert main(["inspect", str(path)]) == 0
    out = capsys.readouterr().out
    assert auth.id in out
    assert "own_signature:     valid" in out


def test_module_entry():
    result = subprocess.run(
        [sys.executable, "-m", "pigeon.cli", "keygen"],
        check=True,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    data = json.loads(result.stdout)
    assert data["public_key"]
