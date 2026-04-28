"""
    the script scans files in a specified directory and its subdirectories.
    It loads the YARA rules from the given directory and scans files using
    configurable filters and the loaded rules, then it reports the matches.
"""

from pathlib import Path
import argparse
import json
import sys
import time                          
from datetime import datetime, timezone


"""
    this acts a fail-safe in case the script is run
    without having the yara-python library installed.
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


# yara static analysis engine that scans files for malware using YARA rules.
def should_scan(file_path, file_extensions, max_size):

    """
        checks if a file should be scanned by checking 
        its extension and size against the provided 
        filters in the CLI argument.
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
        loads .yar or .yara files in the specified directory
        then compiles them into a single yara rules object, and returns it.
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
    sources = {} # a dictionary mapping {"rule_name": "file_path"}
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
        it returns a list of match dictionaries, each containing 
        the rule name, tags, metadata, and which string inside 
        the rule triggered the match and at what byte offset.
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
        runs a yara scan on the specified directory using the provided filters and rules.
        then, it loops through the files that pass the filter checks
        and calls the scan_file function to check for matches against the YARA rules.
    """

    files = preview_scan_paths(scan_dirs, exclude_dirs, file_extensions, max_size)
    total_files = len(files)
    print(f"\n{total_files} file(s) queued for scanning.\n")

    found_files = []
    unmatched_files = []

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


# cuckoo sandbox API where files are sent to the 
# local cuckoo sandbox instance for dynamic analysis.
def submit_a_sample_to_cuckoo(file_path, cuckoo_api, api_token=None):

    """ 
        submits a file to the Cuckoo REST API for analysis.
        returns the task ID if successful or None on failure.
    """

    if not Path(file_path).is_file():
        print(f"Error: the specified file path does not exist or is not a file: {file_path}")
        return None

    # it attempts to read the binary of the file in the given filepath
    try:
        with open(file_path, "rb") as a_file:
            files = {"file": (Path(file_path).name, a_file)}
            http_request_header = {"Authorization": f"Bearer {api_token}"} if api_token else {} # attaches the Bearer token to the request header if one was provided.
            response = requests.post(f"{cuckoo_api}/tasks/create/file", files=files, headers=http_request_header, timeout=30)

            # checks the response status for a scccessful submission
            response.raise_for_status()
            task_id = response.json().get("task_id")
            print(f"Sample successfully submitted to Cuckoo Sandbox with task ID: {task_id}")
            return task_id
    except requests.RequestException as err:
        print(f"Error submitting sample to Cuckoo Sandbox: {err}")
        return None


def get_task_status(task_id, cuckoo_api, api_token=None):

    """ 
        retrieves the current status of a submitted task from the Cuckoo Sandbox API.
    """

    try:
        http_request_header = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        response = requests.get(f"{cuckoo_api}/tasks/view/{task_id}", headers=http_request_header, timeout=15)
        response.raise_for_status()
        status = response.json().get("task", {}).get("status") # status of a task moves through pending -> running -> completed -> reported states
        print(f"Current status of task {task_id}: {status}")
        return status
    except requests.RequestException as err:
        print(f"Error retrieving task status from Cuckoo Sandbox: {err}")
        return None


def get_task_report(task_id, cuckoo_api, api_token=None):

    """
        retreives the JSON report for a completed task from the cuckoo API
        once the task status is "reported". it returns None on failure.
    """

    try:
        http_request_header = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        response = requests.get(f"{cuckoo_api}/tasks/report/{task_id}", headers=http_request_header, timeout=30)
        response.raise_for_status()
        print(f"Report for task {task_id} retrieved successfully.")
        report = response.json()
        return report
    except requests.RequestException as err:
        print(f"Error retrieving task report from Cuckoo Sandbox: {err}")
        return None


def wait_for_task_completion(task_id, cuckoo_api, timeout, api_token=None):

    """
        querys the Cuckoo API every 10 seconds until the task
        reaches the "reported" status, a failure state, or the
        timeout threshold is exceeded.

        returns True if the task completed successfully,
        or False if it failed or timed out.
    """

    # Cuckoo task status states:
    # pending   -> task is queued but not yet picked up by the scheduler
    # running   -> task is actively being executed inside the guest VM
    # completed -> guest has finished execution and results are being processed
    # reported  -> report has been fully generated and is ready to retrieve
    # failed_analysis   -> the analysis itself failed inside the guest
    # failed_reporting  -> the analysis ran but report generation failed
    terminal_failure_states = {"failed_analysis", "failed_reporting"}

    print(f"Waiting for Cuckoo analysis to complete (timeout: {timeout} seconds, querying the API every 10 seconds)")

    start_time = time.time()

    while True:
        elapsed = time.time() - start_time # checks if the elapsed time has exceeded the configured timeout threshold.
        if elapsed >= timeout:
            print(
                f"Error: the analysis did not complete within the {timeout} second timeout. "
                f"The task may still be running in Cuckoo. "
                f"You can retrieve the report manually later using task ID: {task_id}"
            )
            return False

        status = get_task_status(task_id, cuckoo_api, api_token)

        # checks if a task is completed successfully and or fails and prints an appropriate message
        if status == "reported":
            print(f"Task {task_id} has completed successfully and the report is ready.")
            return True

        if status in terminal_failure_states:
            print(f"Error: Cuckoo analysis ended in a failure state: '{status}'. No report will be available.")
            return False

        # if the status is still in any of these "pending, running, completed" states,
        # wait for 10 seconds before querying the API for the task status.
        print(f"Task {task_id} is still in progress (status: {status}). Checking again in 10 seconds...")
        time.sleep(10)


# generates the final scan summary report
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


def build_stdout_summary(report):

    """
        extracts a smaller summary from the full Cuckoo report
        safe for printing to the terminal without the output becoming unreadble.
        when the user has not provided an output file path, only this summary is printed to stdout.
    """

    scan = report.get("Scan summary", {})
    dynamic = scan.get("Dynamic analysis", {})
    static = scan.get("Static analysis", {})

    # attempt to extract a trimmed behavioural summary from the cuckoo report
    cuckoo_summary = None
    full_cuckoo_report = dynamic.get("Report")
    if full_cuckoo_report:
        info = full_cuckoo_report.get("info", {})
        signatures = full_cuckoo_report.get("signatures", [])
        # extract only the signature names and severity rather than full detail
        sigature_summary = [
            {
                "name": sig.get("name"),
                "severity": sig.get("severity"),
                "description": sig.get("description"),
            }
            for sig in signatures
        ]
        cuckoo_summary = {
            "task_id": info.get("id"),
            "duration_seconds": info.get("duration"),
            "score": info.get("score"),
            "category": info.get("category"),
            "signatures_triggered": len(sigature_summary),
            "signatures": sigature_summary,
        }

    return {
        "Scan summary": {
            "report_metadata": scan.get("report_metadata"),
            "Static analysis": {
                "Engine": static.get("Engine"),
                "Total files scanned": static.get("Total files scanned"),
                "Number of matched files": static.get("Number of matched files"),
                "Number of unmatched files": static.get("Number of unmatched files"),
                "findings": static.get("findings"),
            },
            "Dynamic analysis": {
                "Engine": dynamic.get("Engine"),
                "Task ID": dynamic.get("Task ID"),
                "Status": dynamic.get("Status"),
                "Summary": cuckoo_summary if cuckoo_summary else "not available",
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


#  cli entry point
def main():

    """
        parses command line arguments, validates inputs, and calls the 
        appropriate functions in the correct order to execute the scan.
    """

    parser = argparse.ArgumentParser(
        description=(
            "A YARA-based file scanner that scans files in specified directories "
            "then performs dynamic analysis using the Cuckoo Sandbox API, "
            "finally it generates a comprehensive report of the findings."
        )
    )

    # directory to a specific file to be analysed.
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

    # directory that will be scanned for files to be analysed with the YARA rules.
    parser.add_argument(
        "--scan-directories", 
        nargs="+", 
        required=True, 
        help="paths to the directories to be scanned."
    )

    # directories to skip during a scan.
    parser.add_argument(
        "--exclude-directories", 
        nargs="*", default=[], 
        help="paths to the directories to be excluded from scanning."
    )

    # file extensions to include in a scan.
    parser.add_argument(
        "--file-extensions", 
        nargs="*", 
        help="specifies the file extensions to include in the scan (e.g., .exe, .dll). If not specified, all files will be scanned."
    )

    # maximum file size to include in a scan.
    parser.add_argument(
        "--max-size", 
        type=int, 
        help="specifies the maximum file size (in bytes) to be scanned. Files larger than this size will be skipped. If not specified, there is no size limit."
    )

    parser.add_argument(
        "--cuckoo-api", 
        default="http://localhost:8090",
        help=(
            "the base URL of the Cuckoo Sandbox REST API (default: http://localhost:8090). "
            "Note: the Cuckoo REST API is started with: cuckoo api --host 127.0.0.1 --port 8090"
        )
    )

    # the Cuckoo REST Bearer token required for each scan request.
    parser.add_argument(
        "--token",
        required=True,
        help="the Cuckoo API Bearer token gotten from ~/.cuckoo/conf/cuckoo.conf"
    )

    # how long to wait for cuckoo to complete the analysis before timing out and exiting the script.
    parser.add_argument(
        "--timeout", 
        type=int, 
        default=300, 
        help="the maximum time (in seconds) to wait for cuckoo to complete the scan before timing out is 300 seconds)"
    )

    # if provided it save the full report to the specified file path in JSON format, otherwise it prints a condensed summary to stdout.
    parser.add_argument(
        "--output", 
        help="the file path to save the full JSON report. If not specified, a condensed summary will be printed to stdout."
    )

    args = parser.parse_args()

    # if the necessary libraries are not available then exit the script with a helpful message.
    if not YARA_AVAILABLE:
        print("Error: the yara-python library is not installed. Please install it using 'pip install yara-python' and try again.")
        sys.exit(1)

    if not REQUESTS_AVAILABLE:
        print("Error: the requests library is not installed. Please install it using 'pip install requests' and try again.")
        sys.exit(1)

    # this ensures that the file extensions are in the correct format,
    # where each extension starts with a dot (e.g., .exe, .dll) and is lowercase.
    extensions = None
    if args.file_extensions:
        extensions = [
            (e if e.startswith(".") else f".{e}").lower()
            for e in args.file_extensions
        ]

    # checks if the sample file provided in the --sample arg 
    # exists within any of the directories from the --scan-directories arg.
    sample_path = Path(args.sample).resolve()
    scan_paths_resolved = [Path(d).resolve() for d in args.scan_directories]

    sample_in_scan_dirs = any(
        str(sample_path).startswith(str(scan_dir))
        for scan_dir in scan_paths_resolved
    )

    if not sample_in_scan_dirs:
        print(
            f"\nWarning: the sample file '{sample_path}' is not located within any of the "
            f"specified scan directories. YARA will not scan the submitted sample file itself. "
            f"Only files found within the scan directories will be checked against the YARA rules. "
            f"If you want YARA to scan the sample, add its parent directory to --scan-directories."
        )

    # starts the yara static analysis.
    print("\nYARA static analysis engine is starting...")

    # loads and compiles the YARA rules from the specified directory.
    rules = load_yara_rules(args.yara_rules_dir)
    if rules is None:
        print("Error: no valid YARA rules were loaded. Please check the rules directory and try again.")
        sys.exit(1)

    # scans all files that pass the filter checks within the specified directories.
    yara_findings = run_scan(
        scan_dirs=args.scan_directories,
        exclude_dirs=args.exclude_directories,
        file_extensions=extensions,
        max_size=args.max_size,
        rules=rules,
    )

    # starts the cuckoo sandbox dynamic analysis by submitting the sample file to the Cuckoo API for analysis.
    print("\nCuckoo Sandbox dynamic analysis is starting...")

    task_id = submit_a_sample_to_cuckoo(args.sample, args.cuckoo_api, args.token)
    cuckoo_report = None

    # checks if a submission was successful by attempting to retrieve the tasd_id.
    # if the submission failed, it prints an error message and skips the dynamic analysis.
    # else the script queries the Cuckoo API for the status of the submitted task.
    if task_id is None:
        print("Error: failed to submit the sample to Cuckoo Sandbox. Dynamic analysis will be skipped.")
    else:
        is_analysis_completed = wait_for_task_completion(task_id, args.cuckoo_api, args.timeout, args.token)

        if is_analysis_completed: # the task reached the "reported" state so the report is now available
            cuckoo_report = get_task_report(task_id, args.cuckoo_api, args.token)
            if cuckoo_report is None:
                print(
                    "Error: failed to retrieve the report from Cuckoo Sandbox. "
                    "Dynamic analysis results will not be included in the final report."
                )
        else: # the task timed out or failed, so the report is not available
            print(
                "Dynamic analysis did not complete successfully. "
                "The report will contain the static analysis results only."
            )

    # combine the findings from both analysis results into a single report dictionary.
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
    if args.output:
        save_report(report, args.output)
    else:
        # otherwise it prints a more readable summary to stdout.
        print("\nJSON Report Summary (condensed — use --output to save the full report)")
        summary = build_stdout_summary(report)
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()