# -*- coding: utf-8 -*-
"""Yara fetcher client module."""
import json

from typing import Any, Optional, Dict
import requests
import plyara
import plyara.utils
from pycti import OpenCTIConnectorHelper
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

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
        existing_rule = None
        rule_key = self.get_rule_key(ruleset_id, rule_name)
        if rule_key in self.yara_cache:
            self.helper.log_debug(f"Retrieving YARA rule {rule_key} from cache.")
            existing_rule = self.yara_cache[rule_key]
        else:
            self.helper.log_debug(f"Retrieving YARA rule {rule_key} from API.")
            ruleset = self._get_yara_ruleset(ruleset_id)
            # Parse the rules to store them in cache
            parser = plyara.Plyara()
            rules = parser.parse_string(ruleset["data"][0]["yara_ruleset_rules"])
            for rule in rules:
                cache_key = self.get_rule_key(ruleset_id, rule["rule_name"])
                self.yara_cache[cache_key] = rule
                if rule["rule_name"] == rule_name:
                    existing_rule = rule

        if existing_rule is not None:
            return existing_rule

        self.helper.log_warning(f"No YARA rule for rule {rule_key}")
        return None

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
