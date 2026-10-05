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
