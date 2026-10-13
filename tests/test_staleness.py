"""Тестове за 'чистата' логика в auditor/staleness.py - обработката на
отговора от PyPI, БЕЗ реална мрежова заявка."""

from auditor.staleness import _latest_release_date


def test_latest_release_date_picks_the_newest():
    fake_pypi_response = {
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2022-06-15T00:00:00Z"}],
        }
    }
    result = _latest_release_date(fake_pypi_response)
    assert result.year == 2022
    assert result.month == 6


def test_latest_release_date_is_none_when_no_releases():
    assert _latest_release_date({"releases": {}}) is None


# ---------------------------------------------------------------------------
# Тестове с "фалшив интернет" (mock) за самата мрежова функция.
# ---------------------------------------------------------------------------
from unittest.mock import patch, Mock

import requests

from auditor.parser import Requirement
from auditor.staleness import check_package_staleness, find_stale_packages


def _fake_response(json_data):
    response = Mock()
    response.json.return_value = json_data
    return response


OLD_PACKAGE = {"releases": {"1.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}]}}
NEW_PACKAGE = {"releases": {"9.0": [{"upload_time_iso_8601": "2999-01-01T00:00:00Z"}]}}


def test_old_package_reports_years_since_release():
    with patch("auditor.staleness.requests.get", return_value=_fake_response(OLD_PACKAGE)):
        info = check_package_staleness("stara-biblioteka")
    assert info["name"] == "stara-biblioteka"
    assert info["last_release_date"] == "2015-01-01"
    assert info["years_since_release"] > 2


def test_network_error_returns_none_instead_of_crashing():
    with patch("auditor.staleness.requests.get", side_effect=requests.RequestException):
        assert check_package_staleness("kakvoto-i-da-e") is None


def test_package_without_releases_returns_none():
    with patch("auditor.staleness.requests.get", return_value=_fake_response({"releases": {}})):
        assert check_package_staleness("prazen") is None


def test_find_stale_packages_reports_only_old_ones_and_asks_once_per_name():
    reqs = [
        Requirement(name="Stara", operator=None, version=None, line_number=1),
        Requirement(name="stara", operator=None, version=None, line_number=2),  # същото име
        Requirement(name="nova", operator=None, version=None, line_number=3),
    ]

    def fake_get(url, timeout):
        return _fake_response(OLD_PACKAGE if "/stara/" in url.lower() else NEW_PACKAGE)

    with patch("auditor.staleness.requests.get", side_effect=fake_get) as get:
        findings = find_stale_packages(reqs)
    assert [f["name"] for f in findings] == ["Stara"]
    assert get.call_count == 2   # Stara/stara = една заявка, nova = втора
