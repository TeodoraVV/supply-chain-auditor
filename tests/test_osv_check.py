"""Тестове за 'чистата' логика в auditor/osv_check.py - тази, която НЕ
изисква интернет (превод на тежест и обединяване на дубликати).
Самата мрежова заявка (find_vulnerable_ids, get_vuln_details) не се
тества тук - за нея би трябвало да се "подмени" requests с фалшив
отговор (mocking), което е по-напреднала тема."""

from auditor.osv_check import _simple_severity, _deduplicate


def test_simple_severity_translates_known_word():
    data = {"database_specific": {"severity": "HIGH"}}
    assert _simple_severity(data) == "Висока"


def test_simple_severity_unknown_when_missing():
    assert _simple_severity({}) == "непозната"


def test_deduplicate_merges_findings_that_reference_each_other():
    """GHSA-... и PYSEC-... понякога описват ЕДНА И СЪЩА новина и се
    сочат взаимно чрез 'aliases' - трябва да остане само едната."""
    details = [
        {
            "id": "PYSEC-2023-74",
            "aliases": ["GHSA-j8r2-6x86-q33q"],
            "summary": "leak", "severity": "Средна", "fixed_versions": ["2.31.0"],
        },
        {
            "id": "GHSA-j8r2-6x86-q33q",
            "aliases": ["PYSEC-2023-74"],
            "summary": "leak", "severity": "Средна", "fixed_versions": ["2.31.0"],
        },
    ]
    kept = _deduplicate("requests", details)
    assert len(kept) == 1
    assert kept[0]["id"] == "GHSA-j8r2-6x86-q33q"  # предпочитаме GHSA записа


def test_deduplicate_keeps_unrelated_findings_separate():
    """Две находки без общи 'aliases' са РАЗЛИЧНИ проблеми и не бива
    да се сливат в едно."""
    details = [
        {"id": "GHSA-aaaa", "aliases": [], "summary": "a", "severity": "Ниска", "fixed_versions": ["1.0"]},
        {"id": "GHSA-bbbb", "aliases": [], "summary": "b", "severity": "Висока", "fixed_versions": ["2.0"]},
    ]
    kept = _deduplicate("requests", details)
    assert len(kept) == 2
