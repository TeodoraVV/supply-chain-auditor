"""Стъпка 4: Проверка за изоставени (unmaintained) библиотеки.

Идеята: питаме официалния каталог на Python библиотеките (PyPI) кога е
излязла последната версия на дадена библиотека. Ако е било преди повече
от STALE_YEARS години, е вероятно никой вече не я поддържа - а ако в нея
се появи дупка, никой няма да я поправи.
"""

import requests
from datetime import datetime, timezone

PYPI_URL = "https://pypi.org/pypi/{}/json"

# След колко години без нова версия смятаме пакета за "изоставен".
STALE_YEARS = 2.0


def _latest_release_date(data: dict):
    """От отговора на PyPI вади датата на НАЙ-НОВИЯ качен файл,
    измежду всички версии някога издадени за тази библиотека."""
    releases = data.get("releases", {})
    dates = []
    for files_for_one_version in releases.values():
        for file_info in files_for_one_version:
            iso_text = file_info.get("upload_time_iso_8601")
            if iso_text:
                # PyPI връща часа във формат "2020-01-01T12:00:00Z";
                # Python иска "+00:00" вместо "Z", затова го подменяме.
                dates.append(datetime.fromisoformat(iso_text.replace("Z", "+00:00")))
    return max(dates) if dates else None


def check_package_staleness(name: str):
    """Пита PyPI за една библиотека. Връща информация за нея,
    или None ако пакетът не съществува/има проблем с връзката."""
    try:
        response = requests.get(PYPI_URL.format(name), timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException:
        return None

    latest = _latest_release_date(data)
    if latest is None:
        return None

    now = datetime.now(timezone.utc)
    years_since = (now - latest).days / 365

    return {
        "name": name,
        "last_release_date": latest.date().isoformat(),
        "years_since_release": round(years_since, 1),
    }


def find_stale_packages(requirements, threshold_years: float = STALE_YEARS):
    """Минава през всички библиотеки от requirements.txt и връща
    находки за онези, които не са пипани от повече от threshold_years."""
    findings = []
    already_checked = set()  # за да не питаме едно и също име два пъти

    for req in requirements:
        key = req.name.lower()
        if key in already_checked:
            continue
        already_checked.add(key)

        info = check_package_staleness(req.name)
        if info and info["years_since_release"] >= threshold_years:
            findings.append(info)

    return findings
