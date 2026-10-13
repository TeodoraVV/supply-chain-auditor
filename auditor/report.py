"""Стъпка 6: Цветен и подреден изход в терминала (вместо голи print() редове).

Библиотеката "rich" рисува таблици и цветен текст направо в терминала.
Тук държим цялата логика за ПОКАЗВАНЕ на резултатите - самите проверки
(auditor/osv_check.py и останалите) не знаят нищо за rich, само връщат
обикновени данни (списъци и речници). Това разделяне е добра практика:
utre можем да сменим начина на показване (например в json), без да
пипаме логиката на проверките.
"""

from rich.console import Console
from rich.table import Table

console = Console()

# На всяка дума за тежест съответства цвят в rich синтаксис.
SEVERITY_STYLES = {
    "Критична": "bold red",
    "Висока": "red",
    "Средна": "yellow",
    "Ниска": "green",
    "непозната": "dim",
}


def _severity_style(severity: str) -> str:
    return SEVERITY_STYLES.get(severity, "white")


def print_requirements(requirements):
    table = Table(title="Прочетени библиотеки")
    table.add_column("Ред", justify="right")
    table.add_column("Библиотека")
    table.add_column("Версия")
    table.add_column("Статус")

    for req in requirements:
        status = "[green]прикрепена[/green]" if req.is_pinned else "[yellow]НЕприкрепена[/yellow]"
        table.add_row(str(req.line_number), req.name, str(req.version), status)

    console.print(table)


def print_osv_findings(findings):
    console.print("\n[bold]--- Проверка в OSV за известни уязвимости ---[/bold]")
    if not findings:
        console.print("[green]Няма намерени известни уязвимости.[/green]")
        return

    table = Table()
    table.add_column("Библиотека")
    table.add_column("Тежест")
    table.add_column("ID")
    table.add_column("Описание", overflow="fold", max_width=50)
    table.add_column("Поправено във версия")

    for f in findings:
        style = _severity_style(f["severity"])
        table.add_row(
            f["package"],
            f"[{style}]{f['severity']}[/{style}]",
            f["id"],
            f["summary"],
            ", ".join(f["fixed_versions"]),
        )

    console.print(table)


def print_typosquat_findings(findings):
    console.print("\n[bold]--- Проверка за подвеждащи имена (typosquatting) ---[/bold]")
    if not findings:
        console.print("[green]Няма подозрителни имена.[/green]")
        return

    for t in findings:
        console.print(
            f"[yellow]ред {t['line_number']}: '{t['name']}' прилича на популярния пакет "
            f"'{t['similar_to']}' - провери дали не е грешка![/yellow]"
        )


def print_stale_findings(findings):
    console.print("\n[bold]--- Проверка за изоставени библиотеки ---[/bold]")
    if not findings:
        console.print("[green]Няма забелязани изоставени библиотеки (или PyPI не отговори).[/green]")
        return

    for s in findings:
        console.print(
            f"[yellow]'{s['name']}': последно издание на {s['last_release_date']} "
            f"(преди {s['years_since_release']} години)[/yellow]"
        )


def print_hash_findings(findings):
    console.print("\n[bold]--- Проверка за липсваща проверка на целостта (хешове) ---[/bold]")
    if not findings:
        console.print("[green]Всички редове имат хешове.[/green]")
        return

    for h in findings:
        console.print(f"[dim]ред {h['line_number']}: '{h['name']}' няма зададен --hash=[/dim]")


def print_confusion_findings(findings):
    console.print("\n[bold]--- Проверка за dependency confusion (имена, непознати на PyPI) ---[/bold]")
    if not findings:
        console.print("[green]Всички имена съществуват в PyPI (или PyPI не отговори).[/green]")
        return

    for c in findings:
        console.print(
            f"[red]ред {c['line_number']}: '{c['name']}' не съществува в PyPI - "
            f"някой може да регистрира това име със зловреден код![/red]"
        )


def print_summary(osv_findings, typo_findings, stale_findings, hash_findings, confusion_findings=()):
    console.print("\n[bold underline]--- Обобщение ---[/bold underline]")
    console.print(f"Известни уязвимости: [bold]{len(osv_findings)}[/bold]")
    console.print(f"Подозрителни имена: [bold]{len(typo_findings)}[/bold]")
    console.print(f"Изоставени библиотеки: [bold]{len(stale_findings)}[/bold]")
    console.print(f"Липсващи хешове: [bold]{len(hash_findings)}[/bold]")
    console.print(f"Непознати на PyPI имена: [bold]{len(confusion_findings)}[/bold]")
