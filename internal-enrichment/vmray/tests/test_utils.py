# -*- coding: utf-8 -*-
"""VMRay connector test file."""

import sys

import pytest

sys.path.append("..")
from src.vmray.utils.utils import (
    deep_get,
    format_domain,
    format_email_address,
    get_score,
)


class TestUtils:
    def test_deep_get(self):
        """
        Test deep_get function, the result should be equal to the compared values
        """
        test_values = {
            "first": "value",
            "second": {"test": "value"},
            "third": {"test": {"test": "value"}},
        }
        # Test to access first layer value
        assert deep_get(test_values, "first") == "value"
        # Test to access second layer value
        assert deep_get(test_values, "second", "test") == "value"
        # Test to access third layer value
        assert deep_get(test_values, "third", "test", "test") == "value"
        # Test with an empty dict
        assert deep_get({}, "first") is None, "Result should be None"
        # Test with data as another type
        assert deep_get("", "first") is None, "Result should be None"
        # Test a custom return type, should return an empty list
        assert isinstance(deep_get(test_values, "wrong-key", default=[]), list)
        # Test a custom return value, should return a specific string
        assert deep_get(test_values, "wrong-key", default="unknown") == "unknown"
        # Test a wrong formatted key proposition
        assert deep_get(test_values, "third..test.test") is None

    @pytest.mark.parametrize(
        "test_input,expected",
        [
            ("https://test.com", "test.com"),
            ("http://test.com", "test.com"),
            ("https://www.test.com", "test.com"),
            ("http://www.test.com", "test.com"),
            ("test.com", "test.com"),
        ],
    )
    def test_format_domain(self, test_input, expected):
        """
        Test format_domain function, the result should be equal to the compared values
        """
        result = format_domain(test_input)
        assert (
            result == expected
        ), f"The tested domain-name {test_input} should be equal to {expected}"

    @pytest.mark.parametrize(
        "test_input,expected",
        [
            ("john-doe@knight.zoo", "john-doe@knight.zoo"),
            (
                "adwadaflnaofijafaifj john-doe@knight.zoo asdawdawd",
                "john-doe@knight.zoo",
            ),
            (
                "\u0412\u0430\u0434\u0438\u043c \u041c\u0435\u043b\u044c\u043d\u0438\u043a <john-doe@knight.zoo>",
                "john-doe@knight.zoo",
            ),
            ("john-doe#knight.zoo", None),
        ],
    )
    def test_format_email_address(self, test_input, expected):
        """
        Test format_email_address function, the result should be equal to the compared values
        """
        result = format_email_address(test_input)
        assert (
            result == expected
        ), f"The tested email-address {test_input} should be equal to {expected}"

    @pytest.mark.parametrize(
        "test_input,expected",
        [("clean", 10), ("suspicious", 80), ("malicious", 100), ("unknown", None)],
    )
    def test_get_score(self, test_input, expected):
        """
        Test get_score function, the result should be equal to the compared values
        """
        result = get_score(test_input)
        assert (
            result == expected
        ), f"The tested verdict {test_input} should be equal to {expected}"
