import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

try:
    from windows_scanner import main as scanner_main

    parser = argparse.ArgumentParser(description="Run the agent scan using fast or full port scan mode.")
    parser.add_argument("--mode", choices=["fast", "full"], default="fast", help="Choose scan mode")
    args = parser.parse_args()
    raise SystemExit(scanner_main(scan_mode=args.mode))
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()
