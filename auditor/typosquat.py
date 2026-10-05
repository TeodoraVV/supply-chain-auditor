"""Стъпка 3: Проверка за typosquatting (подвеждащи имена).

Идеята: сравняваме името на всяка библиотека с малък списък от много
популярни PyPI пакети. Ако името е ПОЧТИ същото като популярен пакет,
но не е точно същото - вероятно е грешка при писане или измамен пакет.

Пример: "reqeusts" прилича много на "requests", но не е той.
"""

import difflib

# Малък списък с много популярни PyPI пакети - достатъчен за демонстрация
# на идеята. В по-голям проект списъкът може да идва от файл или от
# реалната статистика на PyPI (напр. топ 5000 пакета).
POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "pyyaml", "click",
    "pillow", "sqlalchemy", "boto3", "cryptography", "certifi", "urllib3",
    "setuptools", "wheel", "pip", "six", "python-dateutil", "pytz", "idna",
    "charset-normalizer", "jinja2", "markupsafe", "werkzeug", "attrs",
    "packaging", "pyparsing", "colorama", "protobuf", "pyjwt", "cffi",
    "psutil", "lxml", "beautifulsoup4", "scipy", "matplotlib",
    "scikit-learn", "tqdm", "pytest", "coverage", "sphinx", "jsonschema",
    "pyopenssl", "paramiko", "fastapi", "starlette", "uvicorn", "gunicorn",
    "celery", "redis", "pymongo", "psycopg2", "aiohttp", "httpx",
]

# Колко близко трябва да е името, за да го приемем за подозрително.
# 1.0 = идентично, по-ниско число = приема по-различни имена.
SIMILARITY_CUTOFF = 0.82


def _normalize(name: str) -> str:
    """Прави името 'еднакво написано', за да сравняваме честно:
    малки букви, тирета стават долни черти, а лесно бъркащи се
    знаци (1/l, 0/o) се обединяват."""
    name = name.lower().replace("-", "_")
    name = name.replace("1", "l").replace("0", "o")
    return name


def find_typosquats(requirements, popular=POPULAR_PACKAGES, cutoff=SIMILARITY_CUTOFF):
    """Връща списък с находки: библиотеки, чието име силно прилича на
    популярен пакет, но не е точно същото име."""
    normalized_popular = {_normalize(p) for p in popular}
    findings = []

    for req in requirements:
        norm_name = _normalize(req.name)

        # Ако нормализираното име съвпада точно с популярен пакет,
        # това не е проблем (просто различен регистър/тире например).
        if norm_name in normalized_popular:
            continue

        matches = difflib.get_close_matches(norm_name, normalized_popular, n=1, cutoff=cutoff)
        if not matches:
            continue

        # Намираме оригиналното (четимо) име на популярния пакет.
        real_name = next(p for p in popular if _normalize(p) == matches[0])
        findings.append({
            "name": req.name,
            "similar_to": real_name,
            "line_number": req.line_number,
        })

    return findings
