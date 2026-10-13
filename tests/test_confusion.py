"""Тестове за auditor/confusion.py - БЕЗ реален интернет: подаваме
фалшива функция, която се прави на PyPI."""

from auditor.parser import Requirement
from auditor.confusion import find_unregistered_packages


def _req(name, line=1):
    return Requirement(name=name, operator=None, version=None, line_number=line)


def _fake_pypi(name):
    return {"requests": True, "firma-tajna": False}.get(name)  # непознато -> None


def test_unknown_name_is_flagged():
    findings = find_unregistered_packages([_req("firma-tajna", 7)], exists=_fake_pypi)
    assert findings == [{"name": "firma-tajna", "line_number": 7}]


def test_existing_name_is_not_flagged():
    assert find_unregistered_packages([_req("requests")], exists=_fake_pypi) == []


def test_unknown_answer_is_not_flagged():
    """Ако не можем да разберем (няма връзка), не вдигаме фалшива тревога."""
    assert find_unregistered_packages([_req("nesho-si")], exists=_fake_pypi) == []


def test_duplicate_names_are_reported_once():
    reqs = [_req("firma-tajna", 1), _req("Firma-Tajna", 2)]
    assert len(find_unregistered_packages(reqs, exists=_fake_pypi)) == 1
