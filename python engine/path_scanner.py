#!/usr/bin/env python3
"""
YARA Scan Path Preview
Shows which file paths will be scanned when a scan is initiated.
"""

import os
import argparse
import sys


def should_scan(file_path, extensions, max_size):
    # Extension filter
    if extensions:
        if not file_path.lower().endswith(tuple(extensions)):
            return False

    # File size filter
    if max_size is not None:
        try:
            if os.path.getsize(file_path) > max_size:
                return False
        except OSError:
            return False

    return True


def preview_scan_paths(scan_dirs, exclude_dirs, extensions, max_size):
    results = []

    for scan_dir in scan_dirs:
        if not os.path.exists(scan_dir):
            print(f"[!] Skipping missing path: {scan_dir}")
            continue

        for root, dirs, files in os.walk(scan_dir):
            # Remove excluded directories
            dirs[:] = [
                d for d in dirs
                if os.path.join(root, d) not in exclude_dirs
            ]

            for name in files:
                full_path = os.path.join(root, name)

                if should_scan(full_path, extensions, max_size):
                    results.append(full_path)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Preview file paths that will be scanned using YARA"
    )

    parser.add_argument(
        "--scan-dirs",
        nargs="+",
        required=True,
        help="Directories to scan"
    )

    parser.add_argument(
        "--exclude-dirs",
        nargs="*",
        default=[],
        help="Directories to exclude"
    )

    parser.add_argument(
        "--extensions",
        nargs="*",
        help="File extensions to scan (e.g. .exe .dll .py)"
    )

    parser.add_argument(
        "--max-size",
        type=int,
        help="Maximum file size in bytes"
    )

    args = parser.parse_args()

    print("\n[+] Previewing scan scope...\n")

    files = preview_scan_paths(
        scan_dirs=args.scan_dirs,
        exclude_dirs=set(args.exclude_dirs),
        extensions=args.extensions,
        max_size=args.max_size
    )

    for f in files:
        print(f)

    print(f"\n[+] Total files to be scanned: {len(files)}")


if __name__ == "__main__":
    main()