"""
Test fixture: Generates rapid large output stream to test bounded reader DoS defense.
"""
import sys

if __name__ == "__main__":
    chunk = "A" * 4096 + "\n"
    # Write 500 chunks = ~2MB of data quickly
    for _ in range(500):
        try:
            sys.stdout.write(chunk)
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            break
