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


# ---------------------------------------------------------------------------
# Тестове с "фалшив интернет" (mock): подменяме requests.post / requests.get,
# така че да не се излиза в мрежата, а да получим готов отговор.
# ---------------------------------------------------------------------------
from unittest.mock import patch, Mock

from auditor.parser import Requirement
from auditor.osv_check import find_vulnerable_ids, get_vuln_details, scan


def _fake_response(json_data):
    """Прави фалшив отговор, който 'казва' json_data при .json()."""
    response = Mock()
    response.json.return_value = json_data
    return response


def _pinned(name, version, line=1):
    return Requirement(name=name, operator="==", version=version, line_number=line)


def test_find_vulnerable_ids_matches_results_to_packages():
    reqs = [_pinned("requests", "2.25.0"), _pinned("flask", "3.0.0")]
    fake = _fake_response({"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]})
    with patch("auditor.osv_check.requests.post", return_value=fake) as post:
        found = find_vulnerable_ids(reqs)
    assert found == {"requests": ["GHSA-1"]}   # flask няма находки
    post.assert_called_once()                   # ЕДНА обща заявка, не по една


def test_find_vulnerable_ids_skips_unpinned_without_asking_osv():
    reqs = [Requirement(name="django", operator=">=", version="3.0", line_number=1)]
    with patch("auditor.osv_check.requests.post") as post:
        assert find_vulnerable_ids(reqs) == {}
    post.assert_not_called()                    # нищо за питане -> няма заявка


def test_get_vuln_details_extracts_severity_and_fixed_version():
    data = {
        "summary": "Leaks headers",
        "aliases": ["PYSEC-1"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}],
    }
    with patch("auditor.osv_check.requests.get", return_value=_fake_response(data)):
        details = get_vuln_details("GHSA-1")
    assert details["severity"] == "Висока"
    assert details["fixed_versions"] == ["2.31.0"]
    assert details["aliases"] == ["PYSEC-1"]


def test_get_vuln_details_uses_placeholder_when_no_fix_known():
    with patch("auditor.osv_check.requests.get", return_value=_fake_response({"summary": "x"})):
        assert get_vuln_details("GHSA-2")["fixed_versions"] == ["няма посочена"]


def test_scan_returns_deduplicated_findings():
    """Цялата верига: batch -> подробности -> обединяване на дубликати."""
    post_reply = _fake_response({"results": [{"vulns": [{"id": "PYSEC-1"}, {"id": "GHSA-1"}]}]})
    details = {
        "PYSEC-1": {"summary": "s", "aliases": ["GHSA-1"], "database_specific": {"severity": "LOW"}},
        "GHSA-1": {"summary": "s", "aliases": ["PYSEC-1"], "database_specific": {"severity": "LOW"}},
    }

    def fake_get(url, timeout):
        return _fake_response(details[url.rsplit("/", 1)[1]])

    with patch("auditor.osv_check.requests.post", return_value=post_reply), \
         patch("auditor.osv_check.requests.get", side_effect=fake_get):
        findings = scan([_pinned("requests", "2.25.0")])
    assert len(findings) == 1
    assert findings[0]["id"] == "GHSA-1"
    assert findings[0]["package"] == "requests"
