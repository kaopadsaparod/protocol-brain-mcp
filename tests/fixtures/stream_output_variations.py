"""
Test fixture for validating bounded subprocess streaming reader behaviors:
- large stdout
- large stderr
- simultaneous stdout and stderr
- moderate output between max_store and flood limit
- child process spawning to test recursive termination
"""
import subprocess
import sys
import time


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "stdout_large"

    if mode == "stdout_large":
        # 100 KB on stdout
        chunk = "O" * 4096
        for _ in range(25):
            sys.stdout.write(chunk)
            sys.stdout.flush()

    elif mode == "stderr_large":
        # 100 KB on stderr
        chunk = "E" * 4096
        for _ in range(25):
            sys.stderr.write(chunk)
            sys.stderr.flush()

    elif mode == "both_simultaneous":
        # Simultaneous 50 KB on both streams
        for _ in range(12):
            sys.stdout.write("A" * 4096)
            sys.stderr.write("B" * 4096)
            sys.stdout.flush()
            sys.stderr.flush()

    elif mode == "both_moderate":
        # 12 KB on stdout and 12 KB on stderr (combined 24 KB: exceeds 16KB store, below 64KB flood)
        for _ in range(3):
            sys.stdout.write("S" * 4096)
            sys.stderr.write("E" * 4096)
            sys.stdout.flush()
            sys.stderr.flush()

    elif mode == "moderate_truncated":
        # Exactly 24 KB on stdout (exceeds 16KB store limit, but below 64KB flood ceiling)
        for _ in range(6):
            sys.stdout.write("M" * 4096)
        sys.stdout.flush()

    elif mode == "spawn_child_and_sleep":
        # Spawn background sleep child using existing sleep fixture, then parent sleeps
        subprocess.Popen([sys.executable, "tests/fixtures/sleep_process.py", "30"])
        time.sleep(30)

if __name__ == "__main__":
    main()
