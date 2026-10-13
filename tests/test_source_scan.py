"""Тестове за auditor/source_scan.py - режимът "готов сорс код"."""

from auditor.source_scan import scan_source


def _names(reqs):
    return {r.name for r in reqs}


def test_finds_external_imports_and_skips_stdlib_and_local(tmp_path):
    (tmp_path / "app.py").write_text("import os\nimport requests\nfrom helper import f\n")
    (tmp_path / "helper.py").write_text("import json\n")
    reqs, _ = scan_source(tmp_path)
    assert _names(reqs) == {"requests"}


def test_translates_import_name_to_package_name(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\nfrom PIL import Image\n")
    reqs, _ = scan_source(tmp_path)
    assert _names(reqs) == {"PyYAML", "Pillow"}


def test_uses_version_from_requirements_file(tmp_path):
    (tmp_path / "app.py").write_text("import requests\n")
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
    reqs, has_file = scan_source(tmp_path)
    assert has_file is True
    assert reqs[0].version == "2.25.0" and reqs[0].is_pinned


def test_ignores_broken_files_and_venv_folders(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "x.py").write_text("import flask\n")
    reqs, _ = scan_source(tmp_path)
    assert reqs == []
