from auditor.parser import parse_requirements


def test_pinned_version():
    reqs = parse_requirements("requests==2.25.0")
    assert reqs[0].name == "requests"
    assert reqs[0].version == "2.25.0"
    assert reqs[0].is_pinned is True


def test_no_version_is_not_pinned():
    reqs = parse_requirements("flask")
    assert reqs[0].version is None
    assert reqs[0].is_pinned is False


def test_range_is_not_pinned():
    reqs = parse_requirements("django>=3.0")
    assert reqs[0].operator == ">="
    assert reqs[0].is_pinned is False


def test_comments_and_empty_lines_ignored():
    text = "# коментар\n\nrequests==2.25.0  # стара версия\n-r other.txt\n"
    reqs = parse_requirements(text)
    assert len(reqs) == 1
    assert reqs[0].name == "requests"


def test_hashes_across_lines():
    text = "requests==2.25.0 \\\n    --hash=sha256:abc123 \\\n    --hash=sha256:def456\n"
    reqs = parse_requirements(text)
    assert len(reqs) == 1
    assert reqs[0].hashes == ["sha256:abc123", "sha256:def456"]


def test_extras_and_markers():
    reqs = parse_requirements('requests[security]==2.25.0 ; python_version >= "3.8"')
    assert reqs[0].name == "requests"
    assert reqs[0].version == "2.25.0"
