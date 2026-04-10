"""
    the script scans files in a specified directory and its subdirectories.
    It loads the YARA rules from the given directory and scans files using
    configurable filters and the loaded rules, then it reports the matches.
"""

from pathlib import Path
import argparse
import json
import sys
from datetime import datetime, timezone


"""
    this acts a fail-safe in case the script is run
    without having the yara-python library installed.
    it prints a clear error message and exists the script.
"""
try:
    import yara # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


"""
    attemps to import the requests library
    which handles sending HTTP requests to the 
    Cuckoo Sandbox API running on the local device.
"""
try:
    import requests # type: ignore
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False 


# ════════════════════════════════════════════════════════════════════════════
# yara static analysis engine that scans files for malware using YARA rules.
# ════════════════════════════════════════════════════════════════════════════
def should_scan(file_path, file_extensions, max_size):

    """
        checks if a file should be scanned by checking 
        its extension and size against the provided 
        filters in the command argument.
    """

    # extension filter
    if file_extensions and file_path.suffix.lower() not in file_extensions:
        return False

    # file size filter
    if max_size is not None:
        try:
            if file_path.stat().st_size > max_size:
                return False
        except OSError:
            return False

    return True


def preview_scan_paths(scan_dirs, exclude_dirs, file_extensions, max_size):

    """
        scans directories and returns a list 
        of file paths that can be scanned
    """

    results = []

    for directory in scan_dirs:
        base_path = Path(directory)

        if not base_path.exists():
            print(f"Warning: the path {directory} does not exist. Skipping the missing path.")
            continue

        # recursively scan the directory for files that can be scanned
        for file_path in base_path.rglob("*"):
            if not file_path.is_file():
                continue

            # exclude files that are from the excluded directories
            if any(str(file_path).startswith(str(Path(ex))) for ex in exclude_dirs):
                continue

            if should_scan(file_path, file_extensions, max_size):
                results.append(file_path)

    # a list of file paths that can be scanned
    return results


def load_yara_rules(rules_dir):

    """
        loads and compiles YARA rules from the specified directory.
        it loads files with a .yar or .yara extension, compiles them 
        into a single yara.Rules object, and returns it. 
        If no rules are found, it returns None.
    """

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
            print(f"Warning: failed to compile YARA rule file at: {a_file}: {err}")
    
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


def scan_file(file_path, rules):

    """
        scans a single file against the compiled YARA rules. 
        It returns a list of matches, where an empty list 
        means no matches were found.
        Each match is a dictionary containing the rule name, 
        tags, metadata, and matched strings.
    """

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


def run_scan(scan_dirs, exclude_dirs, file_extensions, max_size, rules):

    """
        runs a full yara scan on the target directories 
        using the provided filters and rules.

        It returns:
        - a list of found files with their matches,
        - a list of unmatched file paths, and
        - the total number of files scanned.
    """

    files = preview_scan_paths(scan_dirs, exclude_dirs, file_extensions, max_size)
    total_files = len(files)
    print(f"\n{total_files} file(s) queued for scanning.\n")

    found_files: list[dict] = []
    unmatched_files: list[str] = []

    for current_file_id, file_path in enumerate(files, start=1):
        print(f"File {current_file_id} of {total_files} is being scanned at: {file_path}")

        # store the matches found
        matches = scan_file(file_path, rules)

        if matches:
            found_files.append({"file": str(file_path), "matches": matches})

            # print an alert message for each matched file
            rule_names = ", ".join(m["rule"] for m in matches)
            print(f"Match found at: {file_path}")
            print(f"          Rules triggered: {rule_names}\n")
        else:
            unmatched_files.append(str(file_path))
            print(f"No match found at: {file_path}\n")


    print(
        f"Scan complete, there were {len(found_files)} matched file(s) "
        f"and {len(unmatched_files)} unmatched file(s) "
        f"out of {total_files} total file(s) scanned."
    )

    return found_files, unmatched_files, total_files


# ════════════════════════════════════════════════════════════════════════════
# cuckoo sandbox API where files are sent to local cuckoo sandbox 
# instance for dynamic analysis.
# ════════════════════════════════════════════════════════════════════════════
def submit_a_sample_to_cuckoo(file_path, cuckoo_api):

    """ 
        submits a file to the Cuckoo Sandbox for analysis.
        returns the task ID if successfult or None on failure.
    """

    if not Path(file_path).is_file():
        print(f"Error: the specified file path does not exist or is not a file: {file_path}")
        return None

    # it attempts to read the binary of the file in the given filepath
    try:
        with open(file_path, "rb") as a_file:
            files = {"file": (Path(file_path).name, a_file)}
            response = requests.post(f"{cuckoo_api}/tasks/create/file", files=files, timeout=30)

            # checks the response status for a scccessful submission
            response.raise_for_status()
            task_id = response.json().get("task_id")
            print(f"Sample successfully submitted to Cuckoo Sandbox with task ID: {task_id}")
            return task_id
    except requests.RequestException as err:
        print(f"Error submitting sample to Cuckoo Sandbox: {err}")
        return None


def get_task_status(task_id, cuckoo_api):

    """ 
        retrieves the current status of a 
        submitted task from the Cuckoo Sandbox API.
    """

    try:
        response = requests.get(f"{cuckoo_api}/tasks/view/{task_id}", timeout=15)
        response.raise_for_status()
        status = response.json().get("task", {}).get("status")
        print(f"Current status of task {task_id}: {status}")
        return status
    except requests.RequestException as err:
        print(f"Error retrieving task status from Cuckoo Sandbox: {err}")
        return None


def get_task_report(task_id, cuckoo_api):

    """
        retreives the JSON report for a completed 
        task from the cuckoo sandbox api.
        returns None on failure.
    """

    try:
        response = requests.get(f"{cuckoo_api}/tasks/report/{task_id}", timeout=30)
        response.raise_for_status()
        print(f"Report for task {task_id} retrieved successfully.")
        report = response.json()
        return report
    except requests.RequestException as err:
        print(f"Error retrieving task report from Cuckoo Sandbox: {err}")
        return None


# ════════════════════════════════════════════════════════════════════════════
# generates the final scan summary report
# ════════════════════════════════════════════════════════════════════════════
def build_report(sample_path, yara_findings, task_id, cuckoo_report, scan_dirs):

    """
        produces a single comprehensive summary report of both 
        the yara analysis and the cuckoo sandbox analysis.
    """

    return {
        "Scan summary": {
            "report_metadata": {
                "Time of scan": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "Sample path": sample_path,
                "Directories scanned": scan_dirs,
            },
            "Static analysis": {
                "Engine": "YARA",
                "Total files scanned": yara_findings["total_files"],
                "Number of matched files": len(yara_findings["matches"]),
                "Number of unmatched files": len(yara_findings["unmatched"]),
                "findings": yara_findings["matches"],
            },
            "Dynamic analysis": {
                "Engine": "Cuckoo Sandbox",
                "Task ID": task_id,
                "Status": "completed" if cuckoo_report else "not available",   
                "Report": cuckoo_report
            }
        }
    }


def save_report(report, output_path):

    """
        saves the report to a specified file path in JSON format.
    """

    with open(output_path, "w", encoding="utf-8") as file_handle:
        json.dump(report, file_handle, indent=2)
    print(f"The report has been saved to: {output_path}")


# ════════════════════════════════════════════════════════════════════════════
#  cli entry point
# ════════════════════════════════════════════════════════════════════════════
def main():

    """
        parses command line arguments, loads YARA rules, 
        runs the scan, and then also runs a dynamic analysis 
        of the matched files using the Cuckoo Sandbox API,
        finally it builds a comprehensive report of the 
        findings and saves it to a file or prints it to stdout.
    """

    parser = argparse.ArgumentParser(
        description=(
            "A YARA-based file scanner that scans files in specified directories "
            "then performs dynamic analysis using the Cuckoo Sandbox API, "
            "finally it generates a comprehensive report of the findings."
        )
    )

    # add the arguments to the parser

    # sample arguments
    parser.add_argument(
        "--sample", 
        required=True, 
        help="path to the sample file to be analysed."
    )

    # yara rule arguments
    parser.add_argument(
        "--yara-rules-dir", 
        required=True, 
        help="path to the directory containing YARA rule files (.yar or .yara) to be used for scanning."
    )

    # scan arguments
    parser.add_argument(
        "--scan-directories", 
        nargs="+", 
        required=True, 
        help="paths to the directories to be scanned."
    )

    # exclude arguments
    parser.add_argument(
        "--exclude-directories", 
        nargs="*", default=[], 
        help="paths to the directories to be excluded from scanning."
    )

    # file extension arguments
    parser.add_argument(
        "--file-extensions", 
        nargs="*", 
        help="specifies the file extensions to include in the scan (e.g., .exe, .dll). If not specified, all files will be scanned."
    )

    # size arguments
    parser.add_argument(
        "--max-size", 
        type=int, 
        help="specifies the maximum file size (in bytes) to be scanned. Files larger than this size will be skipped. If not specified, there is no size limit."
    )

    # api arguments
    parser.add_argument(
        "--cuckoo-api", 
        default="http://localhost:8090", 
        help="the base URL of the Cuckoo Sandbox API (default: http://localhost:8090)"
    )

    # timeout arguments
    parser.add_argument(
        "--timeout", 
        type=int, 
        default=300, 
        help="the maximum time (in seconds) to wait for cuckoo to complete the scan before timing out (default: 300 seconds)"
    )

    # output arguments
    parser.add_argument(
        "--output", 
        help="the file path to save the JSON report. If not specified, the report will be printed to stdout."
    )

    args = parser.parse_args()

    #check if the necessary libraries are available before proceeding with the scan.
    if not YARA_AVAILABLE:
        print("Error: the yara-python library is not installed. Please install it using 'pip install yara-python' and try again.")
        sys.exit(1)

    if not REQUESTS_AVAILABLE:
        print("Error: the requests library is not installed. Please install it using 'pip install requests' and try again.")
        sys.exit(1)

    # this ensures that the file extensions are in the correct format,
    # where each extension starts with a dot (e.g., .exe, .dll).
    extensions = None
    if args.file_extensions:
        extensions = [
            e if e.startswith(".") else f".{e}" for e in args.file_extensions
        ]


    # start of the yara static analysis.
    # this loads and compiles the YARA rules 
    # from the specified directory,
    # and if no rules are found, it exits the script.
    print("\nYARA static analysis engine is starting...")

    rules = load_yara_rules(args.yara_rules_dir)
    if rules is None:
        print ("Error: no valid YARA rules were loaded. Please check the rules directory and try again.")
        sys.exit(1)

    # performs a scan of the specified directories using 
    # the loaded YARA rules and the provided filters.
    yara_findings = run_scan(
        scan_dirs=args.scan_directories,
        exclude_dirs=args.exclude_directories,
        file_extensions=extensions,
        max_size=args.max_size,
        rules=rules,
    )


    # start of the cuckoo sandbox dynamic analysis.
    print("\nCuckoo Sandbox dynamic analysis is starting...")

    task_id = submit_a_sample_to_cuckoo(args.sample, args.cuckoo_api)
    if task_id is None:
        print("Error: failed to submit the sample to Cuckoo Sandbox. Dynamic analysis will be skipped.")
        cuckoo_report = None
    else:
        cuckoo_report = get_task_report(task_id, args.cuckoo_api)
        if cuckoo_report is None:
            print(
                "Error: failed to retrieve the report from Cuckoo Sandbox. "
                "Dynamic analysis results will not be included in the final report.")


    # combine the findings from both the yara static
    # analysis and the cuckoo sandbox dynamic analysis.
    print("\nBuilding the final report...")

    report = build_report(
        sample_path=args.sample,
        yara_findings={
            "matches": yara_findings[0],
            "unmatched": yara_findings[1],
            "total_files": yara_findings[2],
        },
        task_id=task_id,
        cuckoo_report=cuckoo_report,
        scan_dirs=args.scan_directories,
    )

    
    # if an output path is provided, it saves the report to that path in JSON format.
    # otherwise, it prints the report to stdout in JSON format.
    if args.output:
        save_report(report, args.output)
    else:
        # prints a summary to stdout
        print("\nJSON Report Summary")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
