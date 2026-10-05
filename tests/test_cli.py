"""Тестове за логиката зад --fail-on в main.py."""

import main


def test_should_fail_true_when_finding_meets_threshold():
    findings = [{"severity": "Критична"}]
    assert main.should_fail(findings, "high") is True


def test_should_fail_false_when_below_threshold():
    findings = [{"severity": "Ниска"}]
    assert main.should_fail(findings, "high") is False


def test_should_fail_false_when_no_threshold_given():
    """Ако потребителят не е поискал --fail-on, никога не проваляме
    изпълнението - находките само се показват информативно."""
    findings = [{"severity": "Критична"}]
    assert main.should_fail(findings, None) is False


def test_should_fail_true_when_exactly_at_threshold():
    findings = [{"severity": "Висока"}]
    assert main.should_fail(findings, "high") is True
