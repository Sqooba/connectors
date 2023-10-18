# -*- coding: utf-8 -*-
"""VMRay connector test file."""

import os
from src.vmray.utils.constants import HASHES_TYPE
from src.vmray.vmray import VMRayConnector
from pathlib import Path
import json
import sys
import pytest
from unittest.mock import patch

sys.path.append("..")


class TestVmray:
    """
    This class is used to test the VMRayConnector.
    The goal of the test in this file is to validate that the given summary was successfully read and converted into a valid bundle.
    The data within the bundle is not validated; the only goal here is to validate that the bundle was built successfully.
    The file tests/resources/report_full.json can be adapted to your needs.
    The output bundle is written to the file tests/resources/bundle.json.
    """

    @classmethod
    def setup_class(cls):
        # Change according to your needs
        # If set to TRUE, the generated bundle will be written to _BUNDLE path
        cls.write_bundle = True

        # Init input file PATH
        cls._CUSTOM_REPORT_IN = "resources/report_dict_custom.json"
        # Init output file PATH
        cls._CUSTOM_REPORT_OUT = "resources/report_str_custom.json"
        cls._BUNDLE = "resources/bundle.json"

        # Read the corresponding files
        cls._ANALYSIS = TestVmray.generate_analysis(
            cls._CUSTOM_REPORT_IN, cls._CUSTOM_REPORT_OUT
        )

        with patch(
            "src.vmray.vmray.OpenCTIConnectorHelper"
        ) as mock_opencti_connector_helper, patch(
            "src.vmray.vmray.EsClient"
        ) as mock_es_client, patch(
            "src.vmray.vmray.YaraFetcher"
        ):
            # Mocked values
            cls.pyctiClient = mock_opencti_connector_helper
            cls.esClient = mock_es_client
            # Initialize the connector
            test_config = (
                Path(__file__).parent.parent.resolve() / "tests/resources/config.yml"
            )
            test_blacklist = (
                Path(__file__).parent.parent.resolve() / "tests/resources/blacklist.yml"
            )
            cls.connector = VMRayConnector(test_config, test_blacklist)

    @classmethod
    def teardown_class(cls):
        # Remove generated string reports
        if Path(cls._CUSTOM_REPORT_OUT).unlink(missing_ok=True):
            os.remove(cls._CUSTOM_REPORT_OUT)

    def test_process_file(self):
        """
        Test the _process_file function, this is the entry point of the connector
        """
        # Mock the values that should be return by the EsClient
        # Here we feed the return values with our test summary
        mock_es_client_instance = self.esClient.return_value
        mock_es_client_instance.search.return_value = {
            "hits": {"total": {"value": 1}, "hits": [{"_source": self._ANALYSIS}]}
        }

        # Create a fake stixFile
        stix_file = {
            "entity_type": "StixFile",
            "standard_id": "",
            "hashes": [{"algorithm": HASHES_TYPE.get("SHA_256"), "hash": "yolo"}],
        }

        # Run the connector
        self.connector._process_file(stix_file)

        # Retrieve the values that the connector should send to openCTI
        # This is the bundle build during the process_file function
        for call in self.pyctiClient.mock_calls:
            if ".send_stix2_bundle" in str(call):
                # Save the bundle
                expected_bundle_json = "".join(call[1])

        # We expect the final result to be a bundle
        assert json.loads(expected_bundle_json)["type"] == "bundle"

        # Write the bundle into the file if configured
        if self.write_bundle:
            with open(self._BUNDLE, "w") as json_file:
                # json.dump(call[1], json_file, indent=2)
                json_file.write(expected_bundle_json)

    @staticmethod
    def generate_analysis(input_file: str, output_file: str) -> str:
        # Open test analysis
        with open(input_file, "r", encoding="utf-8") as dict_file:
            # Format summary field to str
            raw = json.load(dict_file)
            sample_details = raw["sample_details"]
            summary = raw["summary"]
            with open(output_file, "w", encoding="utf-8") as str_file:
                # Write sample_analysis as a dict and summary as a string
                data = {
                    "sample_details": sample_details,
                    "summary": json.dumps(summary),
                }
                # Write the file in the right format
                json.dump(data, str_file)
            # Open the new file and return it
            with open(output_file, "r", encoding="utf-8") as analysis:
                return json.load(analysis)
