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
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Error: Missing dependencies. Please install them with: pip install -r requirements.txt")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Vulnerability Database URL (Example: using a mock database for demonstration)
VULN_DB_URL = "https://raw.githubusercontent.com/example/vscan-dependency-checker/main/vuln_db.json"  # Replace with a real vulnerability database


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans project dependency files for known vulnerabilities.")
    parser.add_argument("file_path", help="Path to the dependency file (e.g., requirements.txt, package.json).")
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
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error loading vulnerability database: {e}")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from vulnerability database: {e}")
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

                match = re.match(r"([a-zA-Z0-9_-]+)([=><]=?)([\d\.]+)", line)  # Flexible version matching
                if match:
                    name, operator, version = match.groups()  # Capture the groups
                    dependencies.append({"name": name, "version": version})
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
                # Clean up version strings (e.g., remove ^, ~, =, >, <)
                version = version.lstrip('^~=><')

                dependencies.append({"name": name, "version": version})
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
        version = dependency['version']

        if name in vulnerability_db:
            vulnerabilities = vulnerability_db[name]
            for vuln in vulnerabilities:
               #Simplified check:  assume a vulnerability is present if dependency version matches reported vulnerable version
               if version == vuln['version']:
                   vulnerable_dependencies.append({
                       "name": name,
                       "version": version,
                       "vulnerability": vuln['description']
                   })
        else:
            logging.debug(f"Dependency '{name}' not found in vulnerability database.")

    return vulnerable_dependencies


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

    vulnerability_db = load_vulnerability_database(VULN_DB_URL)
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


    vulnerable_dependencies = check_vulnerabilities(dependencies, vulnerability_db)

    if vulnerable_dependencies:
        print("Vulnerable Dependencies Found:")
        for dep in vulnerable_dependencies:
            print(f"  - {dep['name']} (Version: {dep['version']}): {dep['vulnerability']}")
    else:
        print("No known vulnerable dependencies found.")


if __name__ == "__main__":
    main()