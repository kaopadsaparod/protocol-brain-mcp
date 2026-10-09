"""
Native Windows Mutation Testing Harness for Protocol Brain MCP.

Bypasses mutmut's Unix-only platform restriction (mutmut requires WSL/SIGXCPU).
Applies AST-based mutation operators across:
- modules/security/confine.py
- modules/security/policy.py
- modules/system/shell_runner.py

Evaluates test sensitivity and calculates Mutant Survival Rate (< 15% pass criteria).
"""
import ast
import copy
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TARGET_FILES = [
    PROJECT_ROOT / "modules" / "security" / "confine.py",
    PROJECT_ROOT / "modules" / "security" / "policy.py",
    PROJECT_ROOT / "modules" / "system" / "shell_runner.py",
]

MODULE_TESTS = {
    "confine.py": [
        "tests/redteam/test_attack_surface.py",
        "tests/redteam/test_branch_coverage.py",
        "tests/test_vault.py",
    ],
    "policy.py": [
        "tests/redteam/test_branch_coverage.py",
        "tests/test_hardened_security.py",
        "tests/test_security_regression.py",
    ],
    "shell_runner.py": [
        "tests/redteam/test_branch_coverage.py",
        "tests/test_system.py",
        "tests/test_hardened_security.py",
    ],
}


class ASTMutator(ast.NodeTransformer):
    """
    Generates mutations by targeting specific AST nodes by index.
    """
    def __init__(self, target_mutation_index: int):
        super().__init__()
        self.target_mutation_index = target_mutation_index
        self.current_mutation_index = 0
        self.applied_mutation_desc = ""

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        new_ops = []
        mutated = False
        for op in node.ops:
            if not mutated:
                self.current_mutation_index += 1
                if self.current_mutation_index == self.target_mutation_index:
                    mutated = True
                    if isinstance(op, ast.Eq):
                        new_ops.append(ast.NotEq())
                        self.applied_mutation_desc = f"Line {node.lineno}: == replaced by !="
                    elif isinstance(op, ast.NotEq):
                        new_ops.append(ast.Eq())
                        self.applied_mutation_desc = f"Line {node.lineno}: != replaced by =="
                    elif isinstance(op, ast.In):
                        new_ops.append(ast.NotIn())
                        self.applied_mutation_desc = f"Line {node.lineno}: 'in' replaced by 'not in'"
                    elif isinstance(op, ast.NotIn):
                        new_ops.append(ast.In())
                        self.applied_mutation_desc = f"Line {node.lineno}: 'not in' replaced by 'in'"
                    elif isinstance(op, ast.Lt):
                        new_ops.append(ast.GtE())
                        self.applied_mutation_desc = f"Line {node.lineno}: < replaced by >="
                    elif isinstance(op, ast.Gt):
                        new_ops.append(ast.LtE())
                        self.applied_mutation_desc = f"Line {node.lineno}: > replaced by <="
                    elif isinstance(op, ast.LtE):
                        new_ops.append(ast.Gt())
                        self.applied_mutation_desc = f"Line {node.lineno}: <= replaced by >"
                    elif isinstance(op, ast.GtE):
                        new_ops.append(ast.Lt())
                        self.applied_mutation_desc = f"Line {node.lineno}: >= replaced by <"
                    else:
                        new_ops.append(op)
                    continue
            new_ops.append(op)
        node.ops = new_ops
        return node

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        self.current_mutation_index += 1
        if self.current_mutation_index == self.target_mutation_index:
            if isinstance(node.op, ast.And):
                node.op = ast.Or()
                self.applied_mutation_desc = f"Line {node.lineno}: 'and' replaced by 'or'"
            elif isinstance(node.op, ast.Or):
                node.op = ast.And()
                self.applied_mutation_desc = f"Line {node.lineno}: 'or' replaced by 'and'"
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, bool):
            self.current_mutation_index += 1
            if self.current_mutation_index == self.target_mutation_index:
                node.value = not node.value
                self.applied_mutation_desc = f"Line {node.lineno}: bool inverted to {node.value}"
        return node


def count_mutations(file_path: Path) -> int:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    mutator = ASTMutator(target_mutation_index=-1)
    mutator.visit(tree)
    return mutator.current_mutation_index


def apply_mutation(file_path: Path, index: int) -> Tuple[str, str]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    mutator = ASTMutator(target_mutation_index=index)
    mutated_tree = mutator.visit(copy.deepcopy(tree))
    ast.fix_missing_locations(mutated_tree)
    return ast.unparse(mutated_tree), mutator.applied_mutation_desc


def run_tests(test_files: List[str]) -> bool:
    """Runs targeted test suite. Returns True if tests passed, False if failed/killed."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *test_files,
        "-q",
        "--tb=no",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            timeout=60,
        )
        if proc.returncode != 0:
            err_msg = proc.stdout.decode("utf-8", errors="ignore") + "\n" + proc.stderr.decode("utf-8", errors="ignore")
            # Only print diagnostics if unexpected baseline failure
            if "FAILURES" in err_msg or "ERRORS" in err_msg:
                # Store or print for debug
                pass
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        print("[-] Test run timed out (> 60s)", flush=True)
        return False


def run_mutation_analysis():
    print("=" * 70, flush=True)
    print("PROTOCOL BRAIN MCP — NATIVE WINDOWS MUTATION TESTING SUITE", flush=True)
    print("=" * 70, flush=True)

    # Initial baseline check per module
    print("\n[+] Verifying unmutated baseline tests pass...", flush=True)
    all_target_tests = list({t for tests in MODULE_TESTS.values() for t in tests})
    for mod_name, test_suite in MODULE_TESTS.items():
        if not run_tests(test_suite):
            print(f"[-] Baseline tests for {mod_name} failed!", flush=True)
            sys.exit(1)
        print(f"    Baseline tests for {mod_name} passed cleanly.", flush=True)

    total_mutants = 0
    killed_mutants = 0
    survived_mutants = []

    start_time = time.time()

    for target in TARGET_FILES:
        rel_target = target.relative_to(PROJECT_ROOT)
        target_name = target.name
        test_suite = MODULE_TESTS.get(target_name, all_target_tests)

        print(f"\n[+] Analyzing target: {rel_target} (using {len(test_suite)} test suites)", flush=True)
        original_code = target.read_text(encoding="utf-8")
        num_mutations = count_mutations(target)
        print(f"    Available mutation points: {num_mutations}", flush=True)

        # Sample up to 10 representative mutation points per file for speed & depth
        step = max(1, num_mutations // 10)
        indices_to_test = list(range(1, num_mutations + 1, step))

        for idx in indices_to_test:
            try:
                mutated_code, desc = apply_mutation(target, idx)
                if not desc:
                    continue

                total_mutants += 1
                # Write mutant to disk
                target.write_text(mutated_code, encoding="utf-8")

                passed = run_tests(test_suite)
                if passed:
                    # Mutant survived: tests did NOT catch it!
                    survived_mutants.append((str(rel_target), idx, desc))
                    print(f"  [SURVIVED] #{total_mutants} ({rel_target}:{idx}) - {desc}", flush=True)
                else:
                    # Mutant killed: tests caught the injected mutation!
                    killed_mutants += 1
                    print(f"  [KILLED]   #{total_mutants} ({rel_target}:{idx}) - {desc}", flush=True)
            finally:
                # Always restore original code immediately
                target.write_text(original_code, encoding="utf-8")

    elapsed = time.time() - start_time
    survival_rate = (len(survived_mutants) / total_mutants * 100) if total_mutants > 0 else 0.0
    kill_rate = (killed_mutants / total_mutants * 100) if total_mutants > 0 else 0.0

    print("\n" + "=" * 70, flush=True)
    print("MUTATION TESTING SUMMARY", flush=True)
    print("=" * 70, flush=True)
    print(f"Total Mutants Tested : {total_mutants}", flush=True)
    print(f"Killed Mutants       : {killed_mutants} ({kill_rate:.1f}%)", flush=True)
    print(f"Survived Mutants     : {len(survived_mutants)} ({survival_rate:.1f}%)", flush=True)
    print(f"Elapsed Time         : {elapsed:.2f}s", flush=True)
    print(f"Target Pass Criteria : Survived < 15.0%", flush=True)

    if survival_rate < 15.0:
        print(f"\n[PASS] Mutation testing PASSED! Mutant survival rate is {survival_rate:.1f}% (< 15%).", flush=True)
        return True
    else:
        print(f"\n[FAIL] Mutation testing FAILED! Mutant survival rate {survival_rate:.1f}% exceeds 15% threshold.")
        return False


if __name__ == "__main__":
    success = run_mutation_analysis()
    sys.exit(0 if success else 1)
