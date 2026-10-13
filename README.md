# Software Supply Chain Security Scanner

A command-line tool that audits a Python `requirements.txt` file for the most
common security risks hiding in third-party dependencies — before that code
ever reaches production.

Modern applications are built on dozens of open-source packages maintained by
strangers. Attackers know this, and increasingly target the *supply chain*
(the dependencies) rather than the application itself. This scanner applies a
"shift-left security" approach: catch the risk during development, not after
a breach.

## What it checks

| # | Risk | How it's detected | What you do about it |
|---|------|--------------------|------------------------|
| 1 | **Known vulnerabilities (CVEs)** | Queries the [OSV.dev](https://osv.dev) database for every pinned package/version | Upgrade to the fixed version shown in the report |
| 2 | **Unpinned versions** | Flags any requirement without an exact `==` version | Pin exact versions so builds are reproducible |
| 3 | **Typosquatting** | Compares each package name against a list of popular PyPI packages using string-similarity matching | Double-check the name is spelled correctly on PyPI |
| 4 | **Unmaintained packages** | Checks the PyPI JSON API for the date of the last release | Consider migrating to an actively maintained alternative |
| 5 | **Missing integrity hashes** | Flags requirements without a `--hash=sha256:...` entry | Generate hashes with `pip-compile --generate-hashes` |
| 6 | **Dependency confusion** | Flags names that do not exist on PyPI (anyone could register them with malicious code) | Use the correct public name, or install private packages from a trusted private index |

The scanner **only reads metadata** — it never installs, executes, or
modifies any of the analyzed packages.

## Sample output

```
            Read dependencies
┏━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Line┃ Package    ┃ Version┃ Status       ┃
┡━━━━━╇━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━┩
│   4 │ requests   │ 2.25.0 │ pinned       │
│   8 │ reqeusts   │ 2.31.0 │ pinned       │
└─────┴────────────┴────────┴──────────────┘

--- Known vulnerabilities (OSV) ---
[Critical] PyYAML  GHSA-8q59-q68h-6hv4
    Improper Input Validation in PyYAML
    Fixed in: 5.4

--- Typosquatting ---
line 8: 'reqeusts' looks like the popular package 'requests' - check for a typo!
```

## Installation

```bash
git clone https://github.com/<your-username>/supply-chain-auditor.git
cd supply-chain-auditor
pip install -r requirements.txt
```

## Usage

```bash
# Human-readable, colored report
python main.py requirements.txt

# Machine-readable JSON (for scripts / CI pipelines)
python main.py requirements.txt --format json

# Exit with code 1 if a vulnerability at or above a severity is found
python main.py requirements.txt --fail-on high

# No requirements.txt? Scan a source-code folder (or a single .py file):
# the tool reads the imports and checks the third-party libraries it finds
python main.py ./my_project
```

`--fail-on` accepts `low`, `medium`, `high`, or `critical` and is designed to
be dropped straight into a CI/CD pipeline (e.g. GitHub Actions) to block a
build automatically when a dangerous dependency is introduced.

## Project structure

```
supply-chain-auditor/
├── main.py                  # CLI entry point (argparse)
├── auditor/
│   ├── parser.py             # requirements.txt parsing
│   ├── osv_check.py          # OSV.dev vulnerability lookup + deduplication
│   ├── typosquat.py          # name-similarity check
│   ├── staleness.py          # PyPI "last release" check
│   ├── hash_check.py         # missing --hash= check
│   ├── confusion.py          # names unknown to PyPI (dependency confusion)
│   └── report.py             # colored terminal output (rich)
├── tests/                    # pytest test suite (21 tests)
└── demo_requirements.txt     # intentionally vulnerable sample file
```

## Running the tests

```bash
pip install pytest
python -m pytest
```

## Tech stack

Python 3.10+ · [requests](https://pypi.org/project/requests/) ·
[rich](https://pypi.org/project/rich/) · [OSV.dev API](https://osv.dev) ·
PyPI JSON API · pytest

## Possible future work

- Dependency confusion detection (compare against a list of internal package names)
- Support for other ecosystems (npm, etc.)
- Deeper analysis of transitive dependencies

## Author

Built by Tedi Vasileva as a portfolio project to demonstrate practical
software supply chain security and DevSecOps skills.
