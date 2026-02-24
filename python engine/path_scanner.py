#!/usr/bin/env python3
"""
YARA Scan Path Preview (Pathlib Version)
"""

from pathlib import Path
import argparse


def should_scan(file_path: Path, extensions, max_size):
    # Extension filter
    if extensions:
        if file_path.suffix.lower() not in extensions:
            return False

    # File size filter
    if max_size is not None:
        try:
            if file_path.stat().st_size > max_size:
                return False
        except OSError:
            return False

    return True


def preview_scan_paths(scan_dirs, exclude_dirs, extensions, max_size):
    results = []

    for directory in scan_dirs:
        base_path = Path(directory)

        if not base_path.exists():
            print(f"[!] Skipping missing path: {directory}")
            continue

        for file_path in base_path.rglob("*"):
            if file_path.is_file():

                # Exclusion check
                if any(str(file_path).startswith(str(Path(ex))) for ex in exclude_dirs):
                    continue

                if should_scan(file_path, extensions, max_size):
                    results.append(file_path)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Preview file paths that will be scanned using YARA (pathlib version)"
    )

    parser.add_argument("--scan-dirs", nargs="+", required=True)
    parser.add_argument("--exclude-dirs", nargs="*", default=[])
    parser.add_argument("--extensions", nargs="*")
    parser.add_argument("--max-size", type=int)

    args = parser.parse_args()

    print("\n[+] Previewing scan scope...\n")

    files = preview_scan_paths(
        scan_dirs=args.scan_dirs,
        exclude_dirs=args.exclude_dirs,
        extensions=args.extensions,
        max_size=args.max_size
    )

    for f in files:
        print(f)

    print(f"\n[+] Total files to be scanned: {len(files)}")


if __name__ == "__main__":
    main()