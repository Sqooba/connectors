# -*- coding: utf-8 -*-
"""Yara fetcher client module."""
import json
from typing import Any, Dict, Optional, List, Tuple

import plyara
import plyara.utils
import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from plyara import ParseTypeError

# Custom type to simulate a JSON format.
JSONType = Dict[str, Any]


class YaraFetcher:
    """Yara fetcher. Fetches Yara rules from VMRay"""

    def __init__(
        self, helper: OpenCTIConnectorHelper, vmray_url: str, vmray_api_key: str
    ) -> None:
        """Initialize Yara fetcher."""
        self.helper = helper
        self.url = vmray_url
        self.headers = {"Authorization": "api_key " + vmray_api_key}
        self.parser = plyara.Plyara()
        # Cache to store YARA rules. The key is: ruleset_id::rule_name.
        self.yara_cache = {}
        self.helper.log_info(f"VMRay URL: {vmray_url}")

    def _query(self, url: str) -> Optional[JSONType]:
        """
        Query VMRay API.

        Paramaters
        ----------
        url: str
            * The VMRay url formatted with the ruleset_id
        Returns
        -------
        JSON
            * The JSON formatted result
        Raise
        -------
        requests.exceptions
            * If a request exception occurred
        Exception
            * If the exception is unknown
        """
        self.helper.log_info(f"[VMRay] _query(): {url}")
        # Configure the adapter for the retry strategy.
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        response = None
        try:
            response = http.get(url, headers=self.headers, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VMRay] Http error: {errh}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.ConnectionError as errc:
            self.helper.log_error(f"[VMRay] Error connecting: {errc}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.Timeout as errt:
            self.helper.log_error(f"[VMRay] Timeout error: {errt}")
            self.helper.metric.inc("client_error_count")
        except requests.exceptions.RequestException as err:
            self.helper.log_error(f"[VMRay] Something else happened: {err}")
        except json.JSONDecodeError as err:
            self.helper.metric.inc("client_error_count")
            self.helper.log_error(
                f"[VMRay] Error decoding the json: {err} - {response.text}"
            )
        except Exception as err:
            self.helper.log_error(f"[VMRay] Unknown error {err}")
        # Try content failed, return None value
        return None

    def _get_yara_ruleset(self, ruleset_id: str) -> Optional[JSONType]:
        """
        Retrieve the YARA rules based on the given ruleset id.

        Parameters
        ----------
        ruleset_id: str
            * Ruleset id to retrieve
        Returns
        -------
        JSON:
            * YARA ruleset objects, as JSON
        """
        url = f"{self.url}/rest/yara/{ruleset_id}"
        return self._query(url)

    def get_yara_rule(self, ruleset_id: str, rule_name: str) -> Optional[JSONType]:
        """
        Retrieve a Yara rule based on the ruleset id and rule name.

        Parameters
        ----------
        ruleset_id: str
            * Ruleset id to retrieve
        rule_name: str
            * Rule name to retrieve
        Returns
        -------
        JSON
            * YARA rule object as JSON (as parsed by plyara)
        """
        # Lookup in the cache for the rule, otherwise, request VMRay API.
        self.parser.clear()
        rule_key = self.get_rule_key(ruleset_id, rule_name)
        existing_rule = self.yara_cache.get(rule_key)

        if existing_rule is not None:
            self.helper.log_debug(f"Retrieving YARA rule {rule_key} from cache.")
            return existing_rule

        self.helper.log_debug(f"Retrieving YARA rule {rule_key} from API.")
        ruleset_data = self._get_yara_ruleset(ruleset_id)["data"]

        if ruleset_data is None:
            self.helper.log_warning(f"No YARA rule for rule {rule_key}")
            return None

        rules, err_count = self.parse_yara_rule(
            ruleset_data[0].get("yara_ruleset_rules", "")
        )
        self.helper.log_debug(
            f"The yara parser returned {len(rules)} parsed rules and {err_count} error(s)"
        )

        matching_rule = None
        for rule in rules:
            cache_key = self.get_rule_key(ruleset_id, rule["rule_name"])
            # Populate the cache
            self.yara_cache[cache_key] = rule
            if rule["rule_name"] == rule_name:
                matching_rule = rule

        if matching_rule is not None:
            return matching_rule

        self.helper.log_warning(f"No YARA rule for rule {rule_key}")
        return None

    def parse_yara_rule(self, ruleset: str) -> Tuple[List[str], int]:
        """
        Parse Yara rules based on the ruleset. Try to parse the whole ruleset first, split it rule by rule if it fails.

        Parameters
        ----------
        ruleset: str
            * Ruleset string to parse
        Returns
        -------
        Tuple[List[str], int]
            * A List of rules parsed
            * The number of rule(s) skip due to error
        """
        try:
            # Try to parse the entire rules file
            return self.parser.parse_string(ruleset), 0
        except ParseTypeError:
            self.helper.log_info(
                "The Yara file contains errors. It will be chunked and processed rule by rule."
            )
            parsed_rules = []
            unparsed_rules = 0
            # Split the rules
            split = ruleset.split("rule ")
            ruleset_split = ["rule " + rule if rule else "" for rule in split]
            # Process each rule separately
            self.helper.log_debug(f"Processing {len(ruleset_split)} yara rule(s)")
            for r in ruleset_split:
                try:
                    rule_parsed = self.parser.parse_string(r)
                    if rule_parsed:
                        parsed_rules.extend(rule_parsed)
                except ParseTypeError:
                    self.helper.log_error(
                        f"The rule {r} could not be parsed, skipping.."
                    )
                    unparsed_rules += 1
                    continue
            return parsed_rules, unparsed_rules

    @staticmethod
    def get_rule_key(ruleset_id: str, rule_name: str) -> str:
        """
        Concatenate the ruleset id and the rule name in a specific format.

        Parameters
        ----------
        ruleset_id: str
            * Ruleset id add to the string
        rule_name: str
            * Rule name add to the string
        Returns
        -------
        str:
            * The string correctly formatted
        """
        return f"{ruleset_id}::{rule_name}"
