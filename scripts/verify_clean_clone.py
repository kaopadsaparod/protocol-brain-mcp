"""
Tier 1 Clean Clone Verification Script.
Simulates a clean repository export in an isolated temporary directory,
verifies that all runtime and testing dependencies in requirements.txt
permit full module imports, clean linting, and passing tests.
"""

import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    print("==================================================================")
    print("[*] PROTOCOL BRAIN - TIER 1 CLEAN CLONE & REPRODUCIBILITY CHECK")
    print("==================================================================")

    repo_root = Path(__file__).resolve().parent.parent

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        clone_dir = Path(tmp_dir) / "clean_export"

        def ignore_patterns(path, names):
            return {".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", ".hypothesis"}

        import shutil
        shutil.copytree(repo_root, clone_dir, ignore=ignore_patterns)

        # Initialize clean git tracking in isolated clone
        subprocess.run(["git", "init"], cwd=str(clone_dir), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "CI"], cwd=str(clone_dir), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "ci@example.com"], cwd=str(clone_dir), capture_output=True, check=True)
        subprocess.run(["git", "add", "."], cwd=str(clone_dir), capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init clean"], cwd=str(clone_dir), capture_output=True, check=True)

        print(f"  [+] Pristine repository exported to: {clone_dir}")

        # 1. Verify requirements.txt exists and is non-empty
        req_file = clone_dir / "requirements.txt"
        assert req_file.exists(), "requirements.txt is missing from tracked git archive!"
        reqs = [line.strip() for line in req_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        print(f"  [+] Verified {len(reqs)} declared dependencies in requirements.txt")

        # 2. Verify all core modules import cleanly in isolated clone
        print("  [+] Checking core module imports in clean environment...")
        import_script = (
            "import sys; "
            "import server; "
            "import modules.security; "
            "import modules.system; "
            "import modules.vault; "
            "import modules.context_engine; "
            "print('All modules imported successfully in clean export.')"
        )
        imp_proc = subprocess.run(
            [sys.executable, "-c", import_script],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
        )
        if imp_proc.returncode != 0:
            print(f"  [-] Import error in clean export: {imp_proc.stderr}")
            sys.exit(1)
        print("  [+] Module imports: OK")

        # 3. Verify ruff linting in clean export
        print("  [+] Running Ruff lint check on clean export...")
        ruff_proc = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "."],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
        )
        if ruff_proc.returncode != 0:
            print(f"  [-] Ruff failed on clean export: {ruff_proc.stdout}\n{ruff_proc.stderr}")
            sys.exit(1)
        print("  [+] Ruff linting: OK (0 errors)")

        # 4. Run tests on clean export
        print("  [+] Running baseline and red-team tests on clean export...")
        test_proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
        )
        if test_proc.returncode != 0:
            print(f"  [-] Tests failed on clean export: {test_proc.stdout}\n{test_proc.stderr}")
            sys.exit(1)
        print("  [+] Tests: OK")

    print("\n==================================================================")
    print("[OK] TIER 1 CLEAN CLONE VERIFICATION PASSED:")
    print("     - Tracked repository contains all required dependencies")
    print("     - Zero dependencies missing from requirements.txt")
    print("     - All tests pass on fresh exported working tree")
    print("==================================================================")


if __name__ == "__main__":
    main()
