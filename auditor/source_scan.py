"""Режим "готов сорс код": вместо requirements.txt програмата чете самите
.py файлове, намира кои външни библиотеки се внасят (import) и ги проверява.

Как работи:
  1. Обхожда папката и намира всички .py файлове (без .venv, .git и т.н.).
  2. Чете всеки файл с модула `ast` (вградения четец на Python код) и
     събира имената от редовете `import x` и `from x import y`.
  3. Изхвърля вградените библиотеки (os, sys, json...) и собствените
     файлове на проекта - остават само външните.
  4. Превежда името за import към името на пакета в PyPI
     (напр. `yaml` -> `PyYAML`), защото понякога са различни.
  5. Ако в папката има requirements.txt, взима версиите оттам.
     Иначе пробва да види коя версия е инсталирана на този компютър.
"""

import ast
import os
import sys
from importlib import metadata
from pathlib import Path

from auditor.parser import Requirement, parse_file

# Папки, в които няма смисъл да търсим (чужд или генериран код).
SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    "site-packages", "build", "dist", ".tox", ".mypy_cache", ".pytest_cache",
}

# Случаите, в които името за import се различава от името в PyPI.
IMPORT_TO_PACKAGE = {
    "yaml": "PyYAML",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "PyJWT",
    "serial": "pyserial",
    "OpenSSL": "pyOpenSSL",
    "Crypto": "pycryptodome",
    "attr": "attrs",
    "google": "protobuf",
    "MySQLdb": "mysqlclient",
    "psycopg2": "psycopg2-binary",
    "skimage": "scikit-image",
    "docx": "python-docx",
    "git": "GitPython",
    "magic": "python-magic",
}


def _normalize(name):
    return name.lower().replace("_", "-")


def find_python_files(root):
    """Връща списък с пътища до всички .py файлове под root."""
    root = Path(root)
    if root.is_file():
        return [root]
    files = []
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        files.extend(Path(folder) / n for n in names if n.endswith(".py"))
    return sorted(files)


def _local_names(root, files):
    """Имената, които са част от самия проект (не са външни библиотеки)."""
    root = Path(root)
    base = root.parent if root.is_file() else root
    names = {f.stem for f in files}
    for f in files:
        try:
            names.update(f.relative_to(base).parts[:-1])
        except ValueError:
            pass
    return names


def collect_imports(files):
    """Връща речник {име_на_import: (файл, ред)} - къде е видяно за първи път."""
    found = {}
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue  # счупен файл - прескачаме го
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.setdefault(alias.name.split(".")[0], (path, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:  # level>0 = относителен import
                    found.setdefault(node.module.split(".")[0], (path, node.lineno))
    return found


def _installed_version(package):
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def scan_source(root):
    """Главната функция. Връща (списък_с_Requirement, има_ли_requirements_файл)."""
    root = Path(root)
    files = find_python_files(root)
    local = _local_names(root, files)
    imports = collect_imports(files)

    # Версии от requirements.txt (ако има такъв в папката).
    declared = {}
    req_file = (root if root.is_dir() else root.parent) / "requirements.txt"
    if req_file.exists():
        for r in parse_file(str(req_file)):
            declared[_normalize(r.name)] = r

    result = {}
    for top, (_path, line) in imports.items():
        if top in sys.stdlib_module_names or top in local or top == "__future__":
            continue
        package = IMPORT_TO_PACKAGE.get(top, top)
        key = _normalize(package)
        if key in declared:
            result[key] = declared[key]
            continue
        installed = _installed_version(package)
        result[key] = Requirement(
            name=package,
            operator="==" if installed else None,
            version=installed,
            line_number=line,
        )
    # Библиотеки, записани във requirements.txt, но невнасяни директно.
    for key, r in declared.items():
        result.setdefault(key, r)

    return list(result.values()), bool(declared)
