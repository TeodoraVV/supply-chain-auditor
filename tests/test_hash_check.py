"""Тестове за auditor/hash_check.py - проверката за липсващи хешове."""

from auditor.parser import Requirement
from auditor.hash_check import find_missing_hashes


def test_missing_hash_is_flagged():
    req = Requirement(name="requests", operator="==", version="2.0.0", hashes=[], line_number=4)
    findings = find_missing_hashes([req])
    assert len(findings) == 1
    assert findings[0]["name"] == "requests"


def test_present_hash_is_not_flagged():
    req = Requirement(
        name="requests", operator="==", version="2.0.0",
        hashes=["sha256:abc123"], line_number=4,
    )
    assert find_missing_hashes([req]) == []
