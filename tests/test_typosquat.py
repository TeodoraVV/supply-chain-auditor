"""Тестове за auditor/typosquat.py - проверката за подвеждащи имена."""

from auditor.parser import Requirement
from auditor.typosquat import find_typosquats


def _req(name):
    """Малка помощна функция: прави фалшив Requirement само с име,
    колкото да проверим typosquat логиката без да четем истински файл."""
    return Requirement(name=name, operator="==", version="1.0.0", line_number=1)


def test_exact_match_is_not_flagged():
    """Точното истинско име не трябва да вдига тревога."""
    assert find_typosquats([_req("requests")]) == []


def test_typo_is_flagged():
    """'reqeusts' трябва да бъде хванато като подобно на 'requests'."""
    findings = find_typosquats([_req("reqeusts")])
    assert len(findings) == 1
    assert findings[0]["similar_to"] == "requests"


def test_unrelated_name_is_not_flagged():
    """Съвсем различно име (например вътрешен пакет на фирма) не бива
    да се бърка с нищо от списъка с популярни пакети."""
    assert find_typosquats([_req("my-internal-tool")]) == []
