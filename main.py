"""Вход в програмата: истински команден интерфейс.

Използване:
    python main.py requirements.txt
    python main.py requirements.txt --format json
    python main.py requirements.txt --fail-on high
    python main.py ./моят_проект          (папка със сорс код)
    python main.py app.py                 (един .py файл)
"""

import argparse
import json
import sys

import os

from auditor.parser import parse_file
from auditor.source_scan import scan_source
from auditor.osv_check import scan
from auditor.typosquat import find_typosquats
from auditor.staleness import find_stale_packages
from auditor.hash_check import find_missing_hashes
from auditor.confusion import find_unregistered_packages

# Колко "тежка" е всяка дума за тежест - по-голямо число = по-опасно.
SEVERITY_RANK = {
    "непозната": 0,
    "Ниска": 1,
    "Средна": 2,
    "Висока": 3,
    "Критична": 4,
}

# Съответствие между английските думи в --fail-on (стандартни в CI/CD
# инструменти) и българските думи за тежест, които връща osv_check.py.
FAIL_ON_CHOICES = {
    "low": "Ниска",
    "medium": "Средна",
    "high": "Висока",
    "critical": "Критична",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Software Supply Chain Security Scanner - одитира requirements.txt за известни рискове."
    )
    parser.add_argument(
        "requirements_file",
        help="Път до requirements.txt, до папка със сорс код или до един .py файл",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Формат на изхода: 'text' (цветен, за човек) или 'json' (за CI/CD). По подразбиране: text.",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_CHOICES.keys()),
        default=None,
        help="Ако има OSV находка с тежест на това ниво или по-висока, "
             "програмата излиза с код 1 (полезно за CI/CD).",
    )
    return parser.parse_args()


def run_all_checks(requirements_file):
    """Минава през всички проверки и връща суровите резултати (без показване)."""
    if os.path.isdir(requirements_file) or requirements_file.endswith(".py"):
        # Режим "сорс код": четем import-ите директно от .py файловете.
        reqs, has_requirements_file = scan_source(requirements_file)
    else:
        reqs = parse_file(requirements_file)
        has_requirements_file = True
    return {
        "requirements": reqs,
        "osv_findings": scan(reqs),
        "typo_findings": find_typosquats(reqs),
        "stale_findings": find_stale_packages(reqs),
        "confusion_findings": find_unregistered_packages(reqs),
        # Без requirements.txt няма къде да има хешове - не вдигаме фалшива тревога.
        "hash_findings": find_missing_hashes(reqs) if has_requirements_file else [],
    }


def print_text_report(results):
    from auditor import report  # внасяме тук, за да не е нужен rich за --format json

    report.print_requirements(results["requirements"])
    report.print_osv_findings(results["osv_findings"])
    report.print_typosquat_findings(results["typo_findings"])
    report.print_stale_findings(results["stale_findings"])
    report.print_hash_findings(results["hash_findings"])
    report.print_confusion_findings(results["confusion_findings"])
    report.print_summary(
        results["osv_findings"], results["typo_findings"],
        results["stale_findings"], results["hash_findings"],
        results["confusion_findings"],
    )


def print_json_report(results):
    requirements_data = [
        {
            "name": r.name,
            "version": r.version,
            "is_pinned": r.is_pinned,
            "line_number": r.line_number,
        }
        for r in results["requirements"]
    ]
    output = {
        "requirements": requirements_data,
        "osv_findings": results["osv_findings"],
        "typo_findings": results["typo_findings"],
        "stale_findings": results["stale_findings"],
        "hash_findings": results["hash_findings"],
        "confusion_findings": results["confusion_findings"],
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def should_fail(osv_findings, fail_on):
    """Връща True, ако някоя OSV находка е с тежест >= прага, зададен с --fail-on."""
    if fail_on is None:
        return False
    threshold_word = FAIL_ON_CHOICES[fail_on]
    threshold_rank = SEVERITY_RANK[threshold_word]
    return any(
        SEVERITY_RANK.get(f["severity"], 0) >= threshold_rank
        for f in osv_findings
    )


def main():
    args = parse_args()
    results = run_all_checks(args.requirements_file)

    if args.format == "json":
        print_json_report(results)
    else:
        print_text_report(results)

    if should_fail(results["osv_findings"], args.fail_on):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
