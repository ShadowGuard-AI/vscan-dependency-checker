#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import json
import re
from typing import List, Dict

try:
    import requests
except ImportError as e:
    print(f"Error: Missing dependencies. Please install them with: pip install -r requirements.txt")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# The vulnerability database source is named by the operator with
# --db-file or --db-url. There is no built in database and no default
# fetch: a run with neither option names no source and exits 1.


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans project dependency files for known vulnerabilities.")
    parser.add_argument("file_path", help="Path to the dependency file (e.g., requirements.txt, package.json).")
    parser.add_argument("--db-file", help="Path to a local vulnerability database JSON file.")
    parser.add_argument("--db-url", help="URL of a vulnerability database JSON file to fetch (explicit timeout of 10 seconds).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser


def load_vulnerability_database(url: str) -> Dict:
    """
    Loads the vulnerability database from the specified URL.

    Args:
        url (str): The URL of the vulnerability database.

    Returns:
        Dict: A dictionary representing the vulnerability database.
             Returns an empty dictionary if there's an error loading the database.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error loading vulnerability database: {e}")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from vulnerability database: {e}")
        return {}


def load_vulnerability_database_file(path: str) -> Dict:
    """Loads the vulnerability database from a local JSON file named by the operator."""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logging.error(f"Error loading vulnerability database file: {e}")
        return {}


def parse_requirements_txt(file_path: str) -> List[Dict[str, str]]:
    """
    Parses a requirements.txt file and extracts dependency names and versions.

    Args:
        file_path (str): The path to the requirements.txt file.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, where each dictionary represents a dependency
                                and contains 'name' and 'version' keys.  Returns an empty list if the file is not found or invalid.
    """
    dependencies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):  # Skip empty lines and comments
                    continue

                # Strip an inline comment or environment marker; neither is part of the requirement.
                core = line.split('#', 1)[0].split(';', 1)[0].strip()
                match = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]+\])?\s*(.*)$", core)
                if match:
                    name, extras, specifier = match.groups()
                    specifier = (specifier or "").strip()
                    first = specifier.split(',', 1)[0].strip()
                    op_match = re.match(r"(===|==|~=|!=|>=|<=|>|<)?\s*([^\s,]+)?", first)
                    operator = (op_match.group(1) or "") if op_match else ""
                    version = (op_match.group(2) or "") if op_match else ""
                    if version.endswith('.*'):
                        version = version[:-2]
                    dependencies.append({"name": name, "version": version,
                                         "operator": operator, "specifier": specifier,
                                         "extras": extras or ""})
                else:
                   logging.warning(f"Could not parse dependency line: {line}")


    except FileNotFoundError:
        logging.error(f"Dependency file not found: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error parsing dependency file: {e}")
        return []
    return dependencies


def parse_package_json(file_path: str) -> List[Dict[str, str]]:
    """
    Parses a package.json file and extracts dependency names and versions.

    Args:
        file_path (str): The path to the package.json file.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, where each dictionary represents a dependency
                                and contains 'name' and 'version' keys. Returns an empty list if the file is not found or invalid.
    """
    dependencies = []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            all_dependencies = {**(data.get('dependencies', {})), **(data.get('devDependencies', {}))}  # Merge dependencies and devDependencies

            for name, version in all_dependencies.items():
                raw = str(version).strip()
                operator = "~=" if raw.startswith('~') else ("==" if raw.startswith('^') else "")
                # Clean up version strings (e.g., remove ^, ~, =, >, <)
                version = raw.lstrip('^~=>< ')

                dependencies.append({"name": name, "version": version,
                                     "operator": operator, "specifier": raw, "extras": ""})
    except FileNotFoundError:
        logging.error(f"Dependency file not found: {file_path}")
        return []
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from dependency file: {e}")
        return []
    except Exception as e:
        logging.error(f"Error parsing dependency file: {e}")
        return []

    return dependencies


def check_vulnerabilities(dependencies: List[Dict[str, str]], vulnerability_db: Dict) -> List[Dict[str, str]]:
    """
    Checks the dependencies against the vulnerability database.

    Args:
        dependencies (List[Dict[str, str]]): A list of dependencies, where each dependency is a dictionary
                                             containing 'name' and 'version' keys.
        vulnerability_db (Dict): The vulnerability database.

    Returns:
        List[Dict[str, str]]: A list of vulnerable dependencies, where each dependency is a dictionary
                                containing 'name', 'version', and 'vulnerability' keys.
    """
    vulnerable_dependencies = []
    for dependency in dependencies:
        name = dependency['name']
        version = dependency.get('version', '')
        operator = dependency.get('operator', '==')

        if not version:
            # An unpinned entry is present, but there is no version to compare.
            logging.info(f"Dependency '{name}' has no pinned version; no version comparison performed.")
            continue

        if name in vulnerability_db:
            vulnerabilities = vulnerability_db[name]
            for vuln in vulnerabilities:
               if version_matches(operator, version, vuln['version']):
                   vulnerable_dependencies.append({
                       "name": name,
                       "version": version,
                       "vulnerability": vuln['description']
                   })
        else:
            logging.debug(f"Dependency '{name}' not found in vulnerability database.")

    return vulnerable_dependencies


def _version_key(text):
    """Sortable key for a version string: numeric parts first, prerelease sorts before release."""
    main_part, _, _suffix = str(text).partition('-')
    nums = []
    for piece in re.split(r"[.+_]", main_part):
        m = re.match(r"(\d+)(.*)$", piece)
        if m:
            nums.append(int(m.group(1)))
            if m.group(2):
                nums.append(m.group(2))
        else:
            nums.append(piece)
    return nums


def _compare_versions(a, b):
    ka, kb = _version_key(a), _version_key(b)
    for x, y in zip(ka, kb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        return -1 if str(x) < str(y) else 1
    if len(ka) == len(kb):
        return 0
    return -1 if len(ka) < len(kb) else 1


def version_matches(operator, version, candidate):
    """True when the database candidate version falls in the dependency specifier range.

    Exact specifiers compare for equality. A tilde specifier accepts the
    candidate when it is at or above the stated version and below the
    next incompatible release (the last stated component may increase).
    Range specifiers compare directly. This compares versions only; it
    does not decide that any version is outdated.
    """
    if operator in ("", "==", "==="):
        return version == candidate
    cmp_result = _compare_versions(candidate, version)
    if operator == "~=":
        if cmp_result < 0:
            return False
        parts = [p for p in re.split(r"[.]", version) if p.isdigit()]
        if len(parts) >= 2:
            upper = parts[:-1]
            upper[-1] = str(int(upper[-1]) + 1)
            upper_text = ".".join(upper)
            return _compare_versions(candidate, upper_text) < 0
        return cmp_result == 0
    if operator == ">=":
        return cmp_result >= 0
    if operator == "<=":
        return cmp_result <= 0
    if operator == ">":
        return cmp_result > 0
    if operator == "<":
        return cmp_result < 0
    if operator == "!=":
        return version != candidate
    return version == candidate


def main():
    """
    Main function to execute the vulnerability scanning process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    file_path = args.file_path
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        sys.exit(1)

    if args.db_file and args.db_url:
        logging.error("Name only one database source: --db-file or --db-url, not both.")
        sys.exit(1)
    if args.db_file:
        vulnerability_db = load_vulnerability_database_file(args.db_file)
    elif args.db_url:
        vulnerability_db = load_vulnerability_database(args.db_url)
    else:
        logging.error("No vulnerability database source named. Pass --db-file <path> or --db-url <url>; nothing was checked.")
        sys.exit(1)
    if not vulnerability_db:
        logging.error("Failed to load vulnerability database. Exiting.")
        sys.exit(1)

    # Determine file type and parse accordingly
    if file_path.endswith("requirements.txt"):
        dependencies = parse_requirements_txt(file_path)
    elif file_path.endswith("package.json"):
        dependencies = parse_package_json(file_path)
    else:
        logging.error("Unsupported file type.  Must be requirements.txt or package.json.")
        sys.exit(1)


    if not dependencies:
        logging.error("No dependencies were parsed from the input file; nothing was checked.")
        sys.exit(1)

    vulnerable_dependencies = check_vulnerabilities(dependencies, vulnerability_db)

    if vulnerable_dependencies:
        print("Vulnerable Dependencies Found:")
        for dep in vulnerable_dependencies:
            print(f"  - {dep['name']} (Version: {dep['version']}): {dep['vulnerability']}")
    else:
        print("No known vulnerable dependencies found.")


if __name__ == "__main__":
    main()