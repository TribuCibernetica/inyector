"""Tests para build_probe_url — la lógica que decide si un payload de
reconocimiento se manda al parámetro real o a uno sintético.
"""

from inyector.utils.url_probe import build_probe_url


def test_mutates_existing_param_in_place():
    url = "http://example.com/page.php?cat=1&lang=es"
    result = build_probe_url(url, "cat", "1'", fallback_name="orm_test")
    assert result == "http://example.com/page.php?cat=1'&lang=es"


def test_appends_param_if_url_has_none():
    url = "http://example.com/page.php"
    result = build_probe_url(url, "cat", "1'", fallback_name="orm_test")
    assert result == "http://example.com/page.php?cat=1'"


def test_appends_synthetic_param_when_no_param_given():
    url = "http://example.com/page.php?id=1"
    result = build_probe_url(url, None, "'", fallback_name="orm_test")
    assert result == "http://example.com/page.php?id=1&orm_test='"


def test_param_not_present_in_query_gets_appended():
    url = "http://example.com/page.php?id=1"
    result = build_probe_url(url, "cat", "1'", fallback_name="orm_test")
    assert result == "http://example.com/page.php?id=1&cat=1'"
