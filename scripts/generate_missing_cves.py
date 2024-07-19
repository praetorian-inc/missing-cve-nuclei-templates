import os
import re
import subprocess
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Categories to search for
categories = {
    "Cross Site Scripting": [
        "Cross-Site Scripting",
        "Cross Site Scripting",
        " xss",
        "reflected ",
    ],
    "SQL Injection": ["SQL injection"],
    "Local File Inclusion": ["local file inclusion", " lfi"],
    "Server Side Request Forgery": ["server side request forgery", " ssrf"],
    "Remote Code Execution": [
        "remote code execution",
        "remote command execution",
        " rce",
    ],
    "Command Injection": ["command injection"],
    "Code Injection": ["code injection"],
    "Template Injection": ["template injection", " ssti"],
    "Prototype Pollution": ["prototype pollution"],
    "Request Smuggling": ["request smuggling"],
    "Open Redirect": ["open redirect"],
    "XML External Entity": ["XML external entity", " xxe"],
    "Path Traversal": ["path traversal", "directory traversal"],
}


class CveObject:
    def __init__(self):
        self.cve = None
        self.category = None
        self.description = None
        self.url = None

    def __init__(self, cve, category, url):
        self.cve = cve
        self.category = category
        self.url = url

    def __str__(self):
        result = f"[ {self.cve} ] [ {self.category} ] [ {self.url} ]"
        if self.description:
            result += f"\n{self.description}\n"
        return result


# Function to process each CVE file
def process_cve_file(cve_repo, nuclei_files_list, cve_file_info, category_filter):
    year, cve_file = cve_file_info
    current_cve = os.path.join(cve_repo, year, cve_file)
    cve = cve_file.split(".")[0]

    noauth = "unauth|no auth"
    avoid = "android|Product&message=Windows"
    juicy = "wordpress|plugin|php|packetstorm|unauth"

    # Exit if CVE is not a file (unexpected type)
    if not os.path.isfile(current_cve):
        return None
    # Exit if CVE already in nuclei-template repo
    if any(cve in nuclei_file for nuclei_file in nuclei_files_list):
        return None

    with open(current_cve, "r", errors="ignore") as _f:
        cve_content = _f.read()

    for category_name, search_terms in categories.items():

        if category_filter is not None and category_name not in category_filter:
            continue

        for search_term in search_terms:
            missing = re.findall(search_term, cve_content, re.IGNORECASE)
            unauth_match = re.search(noauth, cve_content, re.IGNORECASE)
            avoid_match = re.search(avoid, cve_content, re.IGNORECASE)

            if missing and not avoid_match and unauth_match:
                description = re.search(
                    r"### Description\n(.*?)\n### POC", cve_content, re.DOTALL
                )
                cve_obj = CveObject(
                    cve=cve,
                    category=category_name,
                    url=f"https://github.com/trickest/cve/blob/main/{year}/{cve_file}",
                )
                if description:
                    cve_obj.description = description.group(1).strip()

                return cve_obj
    return None


def get_all_files(directory):
    all_files = []

    def _scandir(dir_path):
        with os.scandir(dir_path) as it:
            for entry in it:
                if entry.is_file():
                    all_files.append(os.path.basename(entry.path))
                elif entry.is_dir():
                    _scandir(entry.path)

    _scandir(directory)
    return all_files


if __name__ == "__main__":
    # Handle argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "nuclei_repo",
        help="Path to the projectdiscovery nuclei-template repository.",
    )
    parser.add_argument(
        "cve_repo",
        help="Path to the trickest cve repository.",
    )
    parser.add_argument(
        "-s",
        "--start-year",
        help=f"Starting year to match CVEs, ranges from {1999} to {datetime.now().year}. Defaults to {datetime.now().year}",
        type=int,
        metavar=f"[1999-{datetime.now().year}]",
        default=(datetime.now().year),
        choices=range(1999, datetime.now().year + 1),
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file of script. If argument is not provided, output will not be saved anywhere.",
    )
    parser.add_argument(
        "-u",
        "--update-repos",
        help="Does a git pull on both repositories before processing CVEs.",
        action="store_true",
    )
    parser.add_argument(
        "--list-categories", help="List the categories", action="store_true"
    )
    parser.add_argument(
        "-f", "--filter", help="Filter by category (use commas for multiple)"
    )
    args = parser.parse_args()

    # Quick print list of categories
    if args.list_categories:
        print("[i] List of Categories")
        for category in categories.keys():
            print(f"{category}")
        exit(0)

    if args.filter is not None:
        print("[i] Splitting category filter into list:")
        category_filter = [x.strip() for x in args.filter.split(",")]
        for category in category_filter:
            print(f"  - {category}")
    else:
        category_filter = None

    # Update the repos
    if args.update_repos:
        print(f"[i] Updating {args.nuclei_repo} and {args.cve_repo}")
        git_processes = []
        git_processes.append(subprocess.Popen(["git", "-C", args.nuclei_repo, "pull"]))
        git_processes.append(subprocess.Popen(["git", "-C", args.cve_repo, "pull"]))
        for p in git_processes:
            p.wait()

    # Gather all CVE files by years to process
    cve_files = []
    for dir in os.listdir(args.cve_repo):
        current_year = os.path.join(args.cve_repo, dir)
        if (
            os.path.isdir(current_year)
            and dir.isdigit()
            and int(dir) >= int(args.start_year)
        ):
            for cve_file in os.listdir(current_year):
                cve_files.append((dir, cve_file))

    if args.output:
        print(f"[i] Clearing the output file: {args.output}")
        _f = open(args.output, "w")
        _f.close()

    # Retrieve all files within the nuclei-template for file matching
    nuclei_files_list = get_all_files(args.nuclei_repo)

    # Process CVE files in parallel
    countFound = 0
    with ThreadPoolExecutor() as executor:
        future_to_cve = {
            executor.submit(
                process_cve_file,
                args.cve_repo,
                nuclei_files_list,
                cve_file,
                category_filter,
            ): cve_file
            for cve_file in cve_files
        }
        for future in as_completed(future_to_cve):
            result = future.result()
            if result:
                countFound += 1
                if args.output:
                    with open(args.output, "a") as f:
                        f.write(result + "\n")
                else:
                    print(result)

    print("===== SUMMARY =====")
    print(f"Total CVEs analyzed: {len(cve_files)}")
    print(f"Total CVEs found: {countFound}")
