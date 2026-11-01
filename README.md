# vscan-dependency-checker
Scans project files (e.g., requirements.txt, package.json) for known vulnerable dependencies. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-dependency-checker`

## Usage
`./vscan-dependency-checker [params]`

The tool reads the vulnerability database the operator names, and no other source. Pass `--db-file <path>` for a local JSON database or `--db-url <url>` to fetch one (the fetch uses an explicit 10 second timeout). With no database named, the tool says so and exits 1: nothing was checked, and no network call is made by default.

Matching: an exact specifier (`==`) reports a dependency when its version equals a database version. A tilde specifier (`~=`) reports when a database version falls in the compatible release range for the stated version. Range specifiers (`>=`, `<=`, `>`, `<`, `!=`) compare the database version against the stated bound. An unpinned entry is reported as present with no version to compare, so it cannot produce a version match. The tool does not report outdated versions.

If no dependencies can be parsed from the input file, the run exits 1 and prints no clean result.

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `--db-file`: Path to a local vulnerability database JSON file
- `--db-url`: URL of a vulnerability database JSON file to fetch

## License
Copyright (c) ShadowStrikeHQ
