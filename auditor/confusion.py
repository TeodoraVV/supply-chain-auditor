"""Стъпка 6: Проверка за "dependency confusion" (объркване на зависимости).

Идеята: ако в проекта има име на библиотека, което НЕ съществува в
официалния каталог PyPI (например вътрешна библиотека на фирма или
сгрешено име), всеки човек може да регистрира точно това име в PyPI и да
качи там зловреден код. Ако инсталацията тръгне да търси името в PyPI,
ще свали чуждия код. Затова всяко име, което PyPI не познава, е сигнал
за внимание.
"""

import requests

PYPI_URL = "https://pypi.org/pypi/{}/json"


def package_exists_on_pypi(name: str):
    """Връща True (има го), False (PyPI казва 'не съществува')
    или None (не успяхме да разберем - няма връзка, грешка и т.н.)."""
    try:
        response = requests.get(PYPI_URL.format(name), timeout=15)
    except requests.RequestException:
        return None
    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    return None


def find_unregistered_packages(requirements, exists=package_exists_on_pypi):
    """Връща находка за всяко име, което PyPI не познава.
    Параметърът `exists` позволява в тестовете да подадем фалшива проверка."""
    findings = []
    already_checked = set()

    for req in requirements:
        key = req.name.lower()
        if key in already_checked:
            continue
        already_checked.add(key)

        if exists(req.name) is False:
            findings.append({"name": req.name, "line_number": req.line_number})

    return findings
