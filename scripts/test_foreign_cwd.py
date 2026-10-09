import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def main():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    
    # Run from Windows System32
    cmd = [
        sys.executable,
        "-c",
        "from modules.config import load_config; print('CONFIG_LOADED:', bool(load_config()))",
    ]
    proc = subprocess.run(
        cmd,
        cwd=r"C:\Windows\System32",
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    print("Return code:", proc.returncode)
    print("Stdout:", proc.stdout.strip())
    print("Stderr:", proc.stderr.strip())
    assert proc.returncode == 0
    assert "CONFIG_LOADED: True" in proc.stdout

if __name__ == "__main__":
    main()
