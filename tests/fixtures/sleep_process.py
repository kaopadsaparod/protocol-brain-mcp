"""
Test fixture: Sleep process to verify timeout bounds and process tree cleanup.
"""
import sys
import time

if __name__ == "__main__":
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    time.sleep(seconds)
