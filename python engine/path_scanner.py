"""
    a path scanner script that identifies what files 
    will be scanned based on their extensions and size.
"""

from pathlib import Path
import argparse

"""
    checks if a file should be scanned 
    based on its extension and size
"""
def should_scan(file_path: Path, file_extensions, max_size):
    # extension filter
    if file_extensions:
        if file_path.suffix.lower() not in file_extensions:
            return False

    # file size filter
    if max_size is not None:
        try:
            if file_path.stat().st_size > max_size:
                return False
        except OSError:
            return False

    return True


"""
    scans directories and returns a list 
    of file paths that can be scanned
"""
def preview_scan_paths(scan_dirs, exclude_dirs, file_extensions, max_size):
    results = []

    for directory in scan_dirs:
        base_path = Path(directory)

        if not base_path.exists():
            print(f"Warning: the path {directory} does not exist. Skipping the missing path.")
            continue

        # recursively scan the directory for files that can be scanned
        for file_path in base_path.rglob("*"):
            if file_path.is_file():

                # exclude files that are from the excluded directories
                if any(str(file_path).startswith(str(Path(ex))) for ex in exclude_dirs):
                    continue

                if should_scan(file_path, file_extensions, max_size):
                    results.append(file_path)

    # a list of file paths that can be scanned
    return results

"""
    a CLI entrypoint that parses command line arguments 
    and prints the directories that will be scanned
"""
def main():
    parser = argparse.ArgumentParser(
        description="Preview the directories that will be scanned using the YARA-rules."
    )

    parser.add_argument("--scan-directories", nargs="+", required=True)
    parser.add_argument("--exclude-directories", nargs="*", default=[])
    parser.add_argument("--file-extensions", nargs="*")
    parser.add_argument("--max-size", type=int)

    args = parser.parse_args()

    print("\n Directories being scanned are: \n")

    files = preview_scan_paths(
        scan_dirs=args.scan_directories,
        exclude_dirs=args.exclude_directories,
        file_extensions=args.file_extensions,
        max_size=args.max_size
    )

    for f in files:
        print(f)

    print(f"\n Total files to be scanned: {len(files)}")

"""
    executes the scripts when run directly, 
    but not when imported as a module
"""
if __name__ == "__main__":
    main()