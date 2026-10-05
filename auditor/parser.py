"""Стъпка 1: Четене (парсване) на requirements.txt.

Задачата на този файл е да превърне текстов ред като
    requests==2.25.0
в удобен обект, с който програмата може да работи:
    име = "requests", версия = "2.25.0"
"""

import re
from dataclasses import dataclass, field


@dataclass
class Requirement:
    """Един ред от requirements.txt, разбит на части."""
    name: str                      # името на библиотеката, напр. "requests"
    operator: str | None           # "==", ">=" и т.н. (None ако няма версия)
    version: str | None            # напр. "2.25.0" (None ако няма версия)
    hashes: list[str] = field(default_factory=list)  # "печатите" (sha256), ако има
    line_number: int = 0           # на кой ред във файла е

    @property
    def is_pinned(self) -> bool:
        """Версията е 'прикрепена', само ако е записана точно с ==."""
        return self.operator == "=="


# Шаблон, който "разпознава" реда: име, по желание [extras], оператор, версия.
LINE_PATTERN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"   # името
    r"(?:\[[^\]]*\])?"                             # [extras] - не ни трябва
    r"\s*(?P<op>==|>=|<=|~=|!=|>|<)?"              # оператор (по желание)
    r"\s*(?P<version>[A-Za-z0-9._*+!-]+)?"         # версия (по желание)
)


def parse_line(line: str, line_number: int = 0) -> Requirement | None:
    """Разбива един ред. Връща None, ако редът не е библиотека
    (празен ред, коментар, или опция като '-r other.txt')."""
    # 1. Махаме коментара (всичко след #)
    line = line.split("#", 1)[0].strip()

    # 2. Празен ред или опция (започва с -) -> прескачаме
    if not line or line.startswith("-"):
        return None

    # 3. Отделяме хешовете (--hash=sha256:...) от останалото
    hashes = re.findall(r"--hash=(\S+)", line)
    line = re.sub(r"--hash=\S+", "", line)

    # 4. Махаме "environment markers" (всичко след ;)
    line = line.split(";", 1)[0].strip()

    # 5. Прилагаме шаблона
    match = LINE_PATTERN.match(line)
    if not match:
        return None

    return Requirement(
        name=match.group("name"),
        operator=match.group("op"),
        version=match.group("version") if match.group("op") else None,
        hashes=hashes,
        line_number=line_number,
    )


def parse_requirements(text: str) -> list[Requirement]:
    """Разбива целия текст на файла и връща списък с библиотеки."""
    results = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1                      # номерата на редовете почват от 1
        current = lines[i]
        # Ред, завършващ с \, продължава на следващия ред (често при хешове)
        while current.rstrip().endswith("\\") and i + 1 < len(lines):
            current = current.rstrip()[:-1] + " " + lines[i + 1]
            i += 1
        req = parse_line(current, start)
        if req:
            results.append(req)
        i += 1
    return results


def parse_file(path: str) -> list[Requirement]:
    """Чете файл от диска и го разбива."""
    with open(path, encoding="utf-8") as f:
        return parse_requirements(f.read())