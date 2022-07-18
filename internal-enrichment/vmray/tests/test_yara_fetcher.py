# -*- coding: utf-8 -*-
"""VMRay connector test file."""

import sys
import pytest

sys.path.append("..")
from src.vmray.utils.yara_fetcher import YaraFetcher


class TestYaraFetcher:
    def test_parse_yara_rule(self, mocker):
        """
        Test parse_yara_rule function, the ruleset should be parsed successfully
        """
        helper_mock = mocker.Mock()
        mocker.patch.object(helper_mock, "log_info")
        yara_fetcher = YaraFetcher(helper_mock, "vmray_url", "vmray_api_key")

        # Define the ruleset to parse
        ruleset = """
        rule ExampleRule
        {
            strings:
                $my_text_string = "text here"
                $my_hex_string = { E2 34 A1 C8 23 FB }
    
            condition:
                $my_text_string or $my_hex_string
        }
        """

        # Parse the rule
        result, err_count = yara_fetcher.parse_yara_rule(ruleset)

        # Define the expected rules
        expected_rule = [
            {
                "condition_terms": ["$my_text_string", "or", "$my_hex_string"],
                "raw_condition": "condition:\n"
                "                $my_text_string or $my_hex_string\n"
                "        ",
                "raw_strings": "strings:\n"
                '                $my_text_string = "text here"\n'
                "                $my_hex_string = { E2 34 A1 C8 23 FB }\n"
                "    \n"
                "            ",
                "rule_name": "ExampleRule",
                "start_line": 2,
                "stop_line": 10,
                "strings": [
                    {"name": "$my_text_string", "type": "text", "value": "text here"},
                    {
                        "name": "$my_hex_string",
                        "type": "byte",
                        "value": "{ E2 34 A1 C8 23 FB }",
                    },
                ],
            }
        ]

        # Assert the results
        assert err_count == 0
        assert (
            result == expected_rule
        ), "The result should match the expected parsed rule"
        assert len(result) == 1, "The result length should be equal to 1"

    def test_parse_yara_rule_with_error(self, mocker):
        """
        Test test_parse_yara_rule_with_error function, the ruleset should be parsed successfully
        The ruleset contains errors, it should be chunked and parse correctly
        """
        helper_mock = mocker.Mock()
        mocker.patch.object(helper_mock, "log_info")
        yara_fetcher = YaraFetcher(helper_mock, "vmray_url", "vmray_api_key")

        # Open the ruleset to parse
        with open("resources/yara_rules.txt", "r", encoding="utf-8") as yara_file:
            ruleset = yara_file.read()

        # Parse the rules
        result, err_count = yara_fetcher.parse_yara_rule(ruleset)

        # Assert the result
        assert err_count == 4
        assert len(result) == 96819

    def test_get_yara_rule(self, mocker):
        """
        Test get_yara_rule function, the ruleset should be parsed successfully and the correct rule should
        be returned from the parsed file
        """

        helper_mock = mocker.Mock()
        mocker.patch.object(helper_mock, "log_info")
        yara_fetcher = YaraFetcher(helper_mock, "vmray_url", "vmray_api_key")

        with open("resources/yara_rules.txt", "r", encoding="utf-8") as yara_file:
            ruleset = yara_file.read()

        mocked_ruleset = {"data": [{"yara_ruleset_rules": ruleset}]}
        mocker.patch.object(
            YaraFetcher, "_get_yara_ruleset", return_value=mocked_ruleset
        )

        # Call the yara get_yara_rule function
        result = yara_fetcher.get_yara_rule("yolo", "Phishkit_Xbalti_Signin")

        expected_rule = {
            "condition_terms": [
                "vmray_target_class",
                "==",
                '"web_request"',
                "and",
                "4",
                "of",
                "them",
            ],
            "imports": ["pe", "math"],
            "raw_condition": "condition:\n"
            '        vmray_target_class == "web_request"\n'
            "        and 4 of them\n",
            "raw_strings": "strings:\n"
            '        $s1 = "<title dir=\\"ltr\\">Amazon"\n'
            '        $s2 = "<form name=\\"signineml\\" method=\\"post\\" '
            'id=\\"signineml\\""\n'
            '        $s3 = "#zwimel {"\n'
            "        $s4 = "
            '"{\\"AUI_158613\\":\\"T1\\",\\"AUI_PCI_RISK_BANNER_210084\\":\\"C\\"}"\n'
            '        $s5 = "name=\\"appActionToken\\" '
            'value=\\"tFcFShIeaDFWxVOmmb6ZEj2BOv0toj3D\\">"\n'
            '        $s6 = "<div id=\\"zwimel\\" class=\\"zwimel\\""\n'
            "\n"
            "    ",
            "rule_name": "Phishkit_Xbalti_Signin",
            "start_line": 11470,
            "stop_line": 11483,
            "strings": [
                {"name": "$s1", "type": "text", "value": '<title dir=\\"ltr\\">Amazon'},
                {
                    "name": "$s2",
                    "type": "text",
                    "value": '<form name=\\"signineml\\" method=\\"post\\" '
                    'id=\\"signineml\\"',
                },
                {"name": "$s3", "type": "text", "value": "#zwimel {"},
                {
                    "name": "$s4",
                    "type": "text",
                    "value": '{\\"AUI_158613\\":\\"T1\\",\\"AUI_PCI_RISK_BANNER_210084\\":\\"C\\"}',
                },
                {
                    "name": "$s5",
                    "type": "text",
                    "value": 'name=\\"appActionToken\\" '
                    'value=\\"tFcFShIeaDFWxVOmmb6ZEj2BOv0toj3D\\">',
                },
                {
                    "name": "$s6",
                    "type": "text",
                    "value": '<div id=\\"zwimel\\" class=\\"zwimel\\"',
                },
            ],
        }

        # Assert the results
        assert sorted(result) == sorted(
            expected_rule
        ), "The result should match the expected parsed rule"

    def test_get_yara_rule_cache(self, mocker):
        """
        Test get_yara_rule function, the ruleset should be parsed successfully and the correct rule should
        be returned from the cache
        """
        helper_mock = mocker.Mock()
        mocker.patch.object(helper_mock, "log_info")
        yara_fetcher = YaraFetcher(helper_mock, "vmray_url", "vmray_api_key")

        # Populate the cache
        expected_rule = "yolo-yara-rule"
        yara_fetcher.yara_cache["yolo::yolo-rule"] = expected_rule

        # Call the yara get_yara_rule function
        result = yara_fetcher.get_yara_rule("yolo", "yolo-rule")

        # Assert the results
        assert result == expected_rule
