"""
    the script scans files in a specified directory and its subdirectories.
    It loads the YARA rules from the given directory and scans files using
    configurable filters and the loaded rules, then it reports the matches.
"""

from pathlib import Path
import argparse
import json
import sys
from datetime import datetime, UTC


"""
    this acts a fail-safe in case the script is run
    without having the yara-python library installed.
    It prints a clear error message and exists the script.
"""
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


"""
    checks if a file should be scanned by checking 
    its extension and size against the provided 
    filters in the command argument.
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
    loads and compiles YARA rules from the specified directory.
    it loads files with a .yar or .yara extension, compiles them 
    into a single yara.Rules object, and returns it. 
    If no rules are found, it returns None.
"""
def load_yara_rules(rules_dir):
    rules_path = Path(rules_dir)
    if not rules_path.is_dir():
        print(f"Warning: the directory {rules_dir} does not exist.")
        sys.exit(1)

    rule_files = list(rules_path.glob("*.yar")) + list(rules_path.glob("*.yara"))
    if not rule_files:
        print(f"Warning: there are no .yar or .yara files found in: {rules_dir}")
        return None

    # validates and compiles each rule file individually,
    # skipping any files that fail with a syntax error.
    sources: dict[str, str] = {}
    for a_file in rule_files:
        try:
            yara.compile(filepath=str(a_file))
            sources[a_file.stem] = str(a_file)
        except yara.SyntaxError as err:
            print(f"Warning: failed to compile YARA rule file {a_file}: {err}")
    
    if not sources:
        print(f"Error: no valid YARA rule files found in: {rules_dir}")
        sys.exit(1)

    print(f"Loading {len(sources)} YARA rule file(s) from: {rules_dir}")
    for name in sources:
        print(f"       • {name}.yar")

    try:
        compiled = yara.compile(filepaths=sources)
    except yara.SyntaxError as err:
        print(f"Error: failed to compile YARA rules: {err}")
        sys.exit(1)
    
    return compiled


"""
    scans a single file with the compiled YARA rules. 
    It returns a list of matches, where each match is 
    a dictionary containing the rule name, tags, metadata, and matched strings.
"""
def scan_file(file_path, rules):
    try:
        matches = rules.match(str(file_path), timeout=120)
    except yara.TimeoutError:
        print(f"Warning: the scan of the {file_path} directory has timed-out, restart the scan to try again.")
        return []
    except yara.Error as err:
        print(f"Warning: an error occurred while scanning {file_path}: {err}")
        return []

    # builds a list of matches, where each match is a dictionary 
    # containing the rule name, tags, metadata, and matched strings.
    # the matched strings also show the identifier which is the string 
    # rule in the YARA file that matched the file and offset which 
    # specifies the position in the file where the match was found.
    results = []
    for match in matches:
        results.append(
            {
                "rule": match.rule,
                "tags": list(match.tags),
                "metadata": dict(match.meta),
                "strings": [
                    {
                        "identifier": s.identifier,
                        "offset": s.instances[0].offset if s.instances else None,
                    }
                    for s in match.strings
                ],
            }
        )
    return results


"""
    it works by collecting files to scan based on 
    the provided directories and filters, then it iterates 
    through each file, scanning it with the loaded YARA rules.
    If a file matches any rules, it records the match details and prints an alert.
"""
def run_scan(scan_dirs, exclude_dirs, file_extensions, max_size, rules):
    files = preview_scan_paths(scan_dirs, exclude_dirs, file_extensions, max_size)
    print(f"{len(files)} file(s) queued for scanning.\n")

    found_files: list[dict] = []
    matched_count = 0

    for current_file_id, file_path in enumerate(files, start=1):
        print(f"File {current_file_id} of {len(files)} is being scanned at {file_path}")

        # stores matches founnd
        matches = scan_file(file_path, rules)
        if matches:
            matched_count += 1
            matched_file = {"file": str(file_path), "matches": matches}
            found_files.append(matched_file)

            # print an alert message for each matched file
            rule_names = ", ".join(m["rule"] for m in matches)
            print(f"  Match found at: {file_path}")
            print(f"          Rules matched: {rule_names}")

    print(f"\n Scan complete, there were {matched_count} out of {len(files)} file(s) matched.")
    return found_files


"""
    creates the structure used to return scan results in a consistent format.
    it details the scan time, the directories that were scanned, the total number 
    of matches found, and the list of findings (matched files and their details).
"""
def build_report(findings, scan_dirs):
    return {
        "scan_time": datetime.now(UTC).isoformat(),
        "scanned_directories": scan_dirs,
        "total_matches": len(findings),
        "findings": findings,
    }


"""
    it saves the report to a specified file path in JSON format.
"""
def save_report(report, output_path):
    with open(output_path, "w", encoding="utf-8") as file_handle:
        json.dump(report, file_handle, indent=2)
    print(f"The report has been saved to: {output_path}")


"""
   the CLI entry point that parses command line arguments, 
   loads YARA rules, runs the scan, and generates the report. 
"""
def main():
    if not YARA_AVAILABLE:
        print(
            "Error: yara-python is not installed.\n"
            "Please install it with:  pip install yara-python\n"
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description= "Scan files for malware using the loaded YARA rules."
    )

    # add the arguments to the parser
    parser.add_argument("--scan-directories", nargs="+", required=True)
    parser.add_argument("--exclude-directories", nargs="*", default=[])
    parser.add_argument("--file-extensions", nargs="*")
    parser.add_argument("--max-size", type=int)

    # yara arguments
    parser.add_argument("--yara-rules-dir", required=True)

    # output arguments
    parser.add_argument("--output")

    args = parser.parse_args()

    # this ensures that the file extensions are in the correct format,
    # where each extension starts with a dot (e.g., .exe, .dll).
    extensions = None
    if args.file_extensions:
        extensions = [
            e if e.startswith(".") else f".{e}" for e in args.file_extensions
        ]

    # this loads and compiles the YARA rules from the specified directory,
    # and if no rules are found, it exits the script.
    rules = load_yara_rules(args.yara_rules_dir)
    if rules is None:
        sys.exit(1)

    # performs a scan of the specified directories using 
    # the loaded YARA rules and the provided filters.
    findings = run_scan(
        scan_dirs=args.scan_directories,
        exclude_dirs=args.exclude_directories,
        file_extensions=extensions,
        max_size=args.max_size,
        rules=rules,
    )

    # builds a report of the scan results.
    report = build_report(findings, args.scan_directories)

    # if an output path is provided, it saves the report to that path in JSON format.
    # otherwise, it prints the report to stdout in JSON format.
    if args.output:
        save_report(report, args.output)
    else:
        # prints a summary to stdout
        print("\n--- JSON Report (stdout) ---")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
    