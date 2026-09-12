import argparse

from windows_scanner import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the agent scanner in fast or full port scan mode.")
    parser.add_argument("--mode", choices=["fast", "full"], default=None, help="Choose scan mode")
    args = parser.parse_args()
    raise SystemExit(main(scan_mode=args.mode))
