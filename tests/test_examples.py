import subprocess
import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_examples_run():
    for script in sorted(EXAMPLES.glob("*.py")):
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            cwd=str(script.parent.parent),
        )
        assert result.returncode == 0, f"{script.name}: {result.stderr}\n{result.stdout}"
