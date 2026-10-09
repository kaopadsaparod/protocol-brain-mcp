"""
Tier 1 Test Rigor Verification Script: Proves Tests Have Weight.
Temporarily reverts security mitigations to prove that tests FAIL when protections are absent,
then restores pristine hardened state.
"""

import subprocess
import sys
from pathlib import Path


def run_targeted_test(test_path: str, test_keyword: str) -> int:
    cmd = [sys.executable, "-m", "pytest", test_path, "-k", test_keyword, "-q"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode


def verify_test_weight():
    repo_root = Path(__file__).resolve().parent.parent
    notif_file = repo_root / "modules" / "system" / "notification.py"
    vault_reader = repo_root / "modules" / "vault" / "reader.py"

    original_notif_code = notif_file.read_text(encoding="utf-8")
    original_vault_code = vault_reader.read_text(encoding="utf-8")

    print("==================================================================")
    print("[*] PROTOCOL BRAIN - TIER 1 TEST RIGOR & WEIGHT VERIFICATION")
    print("==================================================================")

    # -----------------------------------------------------------------
    # Drill 1: Toast PowerShell String Interpolation Vulnerability
    # -----------------------------------------------------------------
    print("\n[Drill 1] Testing Toast Notification Injection Weight...")

    # First, baseline with hardened code MUST PASS
    ret_baseline = run_targeted_test("tests/redteam/test_attack_surface.py", "test_toast_notification_never_interpolates_title_or_message_in_argv")
    assert ret_baseline == 0, "Hardened baseline failed unexpectedly!"
    print("  [+] Baseline hardened code: PASSED (Defense Active)")

    # Mutate to vulnerable implementation (direct string interpolation into powershell command)
    vulnerable_notif_code = original_notif_code.replace(
        '["powershell", "-NoProfile", "-NonInteractive", "-Command", _TOAST_PS_SCRIPT]',
        '["powershell", "-NoProfile", "-NonInteractive", "-Command", f"$title = \'{safe_title}\'; $msg = \'{safe_message}\';"]'
    )

    try:
        notif_file.write_text(vulnerable_notif_code, encoding="utf-8")
        ret_vulnerable = run_targeted_test("tests/redteam/test_attack_surface.py", "test_toast_notification_never_interpolates_title_or_message_in_argv")
        if ret_vulnerable != 0:
            print("  [+] Injected flaw detection: FAILED AS EXPECTED (Test has real weight!)")
        else:
            print("  [-] WARNING: Test passed despite simulated vulnerability!")
            sys.exit(1)
    finally:
        notif_file.write_text(original_notif_code, encoding="utf-8")
        print("  [+] Restored hardened notification.py")

    # -----------------------------------------------------------------
    # Drill 2: Vault Hidden Directory (.obsidian) Access Bypass
    # -----------------------------------------------------------------
    print("\n[Drill 2] Testing Vault Hidden Directory (.obsidian) Weight...")

    ret_vault_baseline = run_targeted_test("tests/redteam/test_attack_surface.py", "test_vault_rejects_hidden_and_non_markdown_targets")
    assert ret_vault_baseline == 0, "Hardened baseline failed unexpectedly!"
    print("  [+] Baseline hardened code: PASSED (Defense Active)")

    # Mutate to vulnerable implementation (bypass reader and wikilink protections)
    vulnerable_vault_code = (
        original_vault_code
        .replace("def is_safe_vault_path(target: Path, vault: Path) -> bool:", "def is_safe_vault_path(target: Path, vault: Path) -> bool:\n    return True\n    if False:")
        .replace("def resolve_wikilink_path(vault_path: Path, note_identifier: str) -> Optional[Path]:", "def resolve_wikilink_path(vault_path: Path, note_identifier: str) -> Optional[Path]:\n    return (vault_path / note_identifier).resolve()\n    if False:")
    )

    try:
        vault_reader.write_text(vulnerable_vault_code, encoding="utf-8")
        ret_vault_vulnerable = run_targeted_test("tests/redteam/test_attack_surface.py", "test_vault_rejects_hidden_and_non_markdown_targets")
        if ret_vault_vulnerable != 0:
            print("  [+] Injected flaw detection: FAILED AS EXPECTED (Test has real weight!)")
        else:
            print("  [-] WARNING: Test passed despite simulated vulnerability!")
            sys.exit(1)
    finally:
        vault_reader.write_text(original_vault_code, encoding="utf-8")
        print("  [+] Restored hardened reader.py")

    print("\n==================================================================")
    print("[OK] TEST RIGOR PROVEN: All targeted security tests immediately FAIL")
    print("     when defensive code is removed or regressed.")
    print("==================================================================")


if __name__ == "__main__":
    verify_test_weight()
