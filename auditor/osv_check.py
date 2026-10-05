"""Стъпка 2: Проверка в OSV за известни уязвимости (CVE).

Логиката е на две стъпки:
1. Питаме OSV с име+версия за всяка библиотека -> получаваме само номера (ID).
2. За всеки намерен номер питаме повторно -> получаваме подробности:
   описание, тежест и коя версия е поправила проблема.

Има и трета стъпка: едно и също нещо често е записано под НЯКОЛКО номера
(например GHSA-... и PYSEC-... едновременно), защото различни бази данни
следят една и съща новина. Затова в края обединяваме дубликатите.
"""

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

# OSV пази тежестта на два начина: като точен CVSS код (труден за четене)
# и - за находки от GHSA - като готова дума (LOW/MODERATE/HIGH/CRITICAL)
# в полето database_specific. Превеждаме готовата дума на български.
SEVERITY_TRANSLATIONS = {
    "CRITICAL": "Критична",
    "HIGH": "Висока",
    "MODERATE": "Средна",
    "MEDIUM": "Средна",
    "LOW": "Ниска",
}


def _build_query(req):
    """Прави заявка във формата, който OSV очаква, за една библиотека."""
    return {
        "package": {"name": req.name, "ecosystem": "PyPI"},
        "version": req.version,
    }


def find_vulnerable_ids(requirements):
    """Праща ЕДНА обща заявка (batch) за всички прикрепени библиотеки
    и връща речник: {име_на_библиотека: [списък с ID-та на находки]}.

    Проверяваме само прикрепени версии (==), защото само тогава знаем
    точно коя версия ще бъде инсталирана.
    """
    pinned = [r for r in requirements if r.is_pinned]
    if not pinned:
        return {}

    queries = [_build_query(r) for r in pinned]
    response = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
    response.raise_for_status()  # ще гръмне с ясна грешка, ако нещо е сбъркано
    results = response.json().get("results", [])

    found = {}
    # zip събира двата списъка по двойки: коя библиотека <-> какъв е отговорът за нея
    for req, result in zip(pinned, results):
        vuln_ids = [v["id"] for v in result.get("vulns", [])]
        if vuln_ids:
            found[req.name] = vuln_ids
    return found


def _simple_severity(data: dict) -> str:
    """Опитва се да върне проста дума за тежестта, вместо суров CVSS код."""
    db_severity = data.get("database_specific", {}).get("severity")
    if db_severity:
        return SEVERITY_TRANSLATIONS.get(db_severity.upper(), db_severity)
    return "непозната"


def get_vuln_details(vuln_id):
    """Взима пълните подробности за едно ID: описание, тежест, поправена
    версия и списъка с ДРУГИ номера, с които е известна същата находка
    (полето "aliases") - това ни трябва за обединяването на дубликати."""
    response = requests.get(OSV_VULN_URL.format(vuln_id), timeout=30)
    response.raise_for_status()
    data = response.json()

    summary = data.get("summary") or (data.get("details", "")[:150] + "...")
    severity = _simple_severity(data)

    # Търсим коя версия поправя проблема (полето "fixed" в диапазоните).
    fixed_versions = set()
    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed_versions.add(event["fixed"])

    return {
        "id": vuln_id,
        "aliases": data.get("aliases", []),
        "summary": summary,
        "severity": severity,
        "fixed_versions": sorted(fixed_versions) or ["няма посочена"],
    }


def _deduplicate(package_name, details):
    """Ако две находки се сочат взаимно чрез 'aliases', това е една и съща
    новина под два номера - пазим само едната. Предпочитаме GHSA записите,
    защото обикновено имат по-добро описание и готова дума за тежестта."""
    kept = []
    already_covered_ids = set()

    details_sorted = sorted(details, key=lambda d: 0 if d["id"].startswith("GHSA") else 1)
    for d in details_sorted:
        if d["id"] in already_covered_ids:
            continue
        kept.append({"package": package_name, **d})
        already_covered_ids.add(d["id"])
        already_covered_ids.update(d.get("aliases", []))

    return kept


def scan(requirements):
    """Главна функция: минава през всички стъпки и връща готов списък
    с находки (вече без дубликати), готов за показване."""
    vulnerable = find_vulnerable_ids(requirements)
    findings = []
    for name, ids in vulnerable.items():
        details = [get_vuln_details(vid) for vid in ids]
        findings.extend(_deduplicate(name, details))
    return findings
