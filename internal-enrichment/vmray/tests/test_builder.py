import sys

sys.path.append("..")
from src.vmray.builder import VMRAYBuilder, OpenCtiText
from unittest.mock import MagicMock, PropertyMock
from pathlib import Path
import unittest
import json
import os
from regex import W

from stix2 import (
    Bundle,
    DomainName,
    EmailAddress,
    File,
    Identity,
    Indicator,
    IPv4Address,
    Report,
    URL,
    TLP_AMBER,
)


class TestBuilder(unittest.TestCase):
    """
    This class is use to test the VMRayBuilder class.

    A file named report_dict.json must be created in the tests/ressources directory. Unlike the analysed report, the
    summary key in the report_dict.json must be of type dict. This allow the tester to change according to his needs the
    content of the summary.

    The file is then converted into the same format as the one sent by ES and used by the builder. This file gets removed after the tests.
    """

    @classmethod
    def setUpClass(cls):

        # Mock helper OpenCtiConnector
        cls.helper = MagicMock()
        confidence_level = PropertyMock(return_value=80)
        type(cls.helper).connect_confidence_level = confidence_level

        # Setup author
        cls.author = Identity(
            name="VMRay",
            identity_class="system",
            description="Test description",
            confidence=80,
        )

        # File to work with :
        cls.report_dict = "ressources/report_dict.json"
        cls.report_str = "ressources/report_str.json"

        # Ingest sample analysis, human-readable format
        with open(cls.report_dict, "r", encoding="utf-8") as dict_file:
            # Format summary field to str
            raw = json.load(dict_file)
            sample_details = raw["sample_details"]
            summary = raw["summary"]
            with open(cls.report_str, "w", encoding="utf-8") as str_file:
                # Write sample_analysis as a dict and summary as a string
                data = {
                    "sample_details": sample_details,
                    "summary": json.dumps(summary),
                }
                json.dump(data, str_file)

        # Read final file
        with open(cls.report_str, "r", encoding="utf-8") as analysis:
            cls.analysis = json.load(analysis)

        # Initialize builder
        cls.builder = VMRAYBuilder(cls.author, False, cls.analysis, cls.helper)

        # Initialize custom properties
        cls.custom_props = {
            "x_opencti_created_by_ref": cls.author["id"],
            "x_metis_modified_on_s": False,
        }

    def test_init_builder(self):
        # Test if the source sample is found
        self.assertIsNotNone(self.builder.sample_id)

        # TODO --> Test to remove the source file_0, just to be sure the process stop

        # Initialize a builder with inconsistent analysis should throw an error
        with self.assertRaises(TypeError):
            VMRAYBuilder(self.author, False, "", self.helper)
        with self.assertRaises(KeyError):
            VMRAYBuilder(self.author, False, {}, self.helper)
        with self.assertRaises(TypeError):
            wrong_analysis = {
                "sample_details": {"test": "test"},
                "summary": {},  # Should be of type str
            }
            VMRAYBuilder(self.author, False, wrong_analysis, self.helper)
        with self.assertRaises(TypeError):
            wrong_analysis = {
                "sample_details": 2,  # Should be of type dict
                "summary": "test",
            }
            VMRAYBuilder(self.author, False, wrong_analysis, self.helper)
        with self.assertRaises(KeyError):
            wrong_analysis = {
                "sample_details": {},
                "summary": "",  # Should not be an empty string
            }
            VMRAYBuilder(self.author, False, wrong_analysis, self.helper)

    def test_identity(self):
        """
        Test the identity creation process, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        stix_expected = Identity(
            type="identity",
            spec_version="2.1",
            id="identity--6e6c3293-480a-463c-9b3f-12846e837c4f",
            name="VMRay",
            description="Test description",
            identity_class="system",
            confidence=80,
        )

        # Create the bundle
        raw = self.builder.create_bundle()
        stix_result = raw.objects[0]

        # Run tests
        assert isinstance(
            stix_result, Identity
        ), "Return type should be stix2.v21.sdo.Identity"
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should match"
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertEqual(
            stix_expected.description,
            stix_result.description,
            "Description property should match",
        )
        self.assertEqual(
            stix_expected.identity_class,
            stix_result.identity_class,
            "Identity class property should match",
        )
        self.assertEqual(
            stix_expected.confidence,
            stix_result.confidence,
            "Confidence property should match",
        )

    def test_create_file(self):
        """
        Test create_file function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        # Expected object
        stix_expected = File(
            type="file",
            spec_version="2.1",
            hashes={
                "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
                "md5": "dda9f8dc0028cbfea65fc466386817d3",
                "sha1": "f7f7425ea289e87839c39253f71de72cecd2425f",
                "sha256": "d345ba9e7c6d653856d0b9cd9c7090d7b38f04de58520ab5dac8b22eabcc6b61",
                "ssdeep": "12288:+RBxKM3FMOGPvwz4CkAgDRgThAwxG7ty9Wy2waqxXTu:SBEoMZQkClglkAkG",
            },
            name="uxhvqy.exe",
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        sample = self.builder.summary["files"]["file_0"]
        self.builder.create_file(sample)
        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Run tests
        assert isinstance(
            stix_result, File
        ), "Return type should be stix2.v21.observables.File"
        self.assertEqual(
            len(self.builder.bundle), 1, "The bundle's length should be equal to 1"
        )
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should match"
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertDictEqual(
            stix_expected.hashes,
            stix_result.hashes,
            "Hashes property should be equal to stix_expected hashes",
        )
        self.assertEqual(
            stix_result.name, stix_expected.name, "The name of the file should match"
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        # Test the name of file_1, it should set the filename_1's key name
        sample = self.builder.summary["files"]["file_1"]
        self.builder.create_file(sample)
        stix_result = self.builder.bundle[1]
        self.assertEqual(
            stix_result.name, "testName.exe", "The name of the file should match"
        )
        # Test the name of a file with no name value, it should take the hash-256
        sample = self.builder.summary["files"]["file_2"]
        self.builder.create_file(sample)
        stix_result = self.builder.bundle[2]
        self.assertEqual(
            stix_result.name,
            "7ae0ec1732c1e565e532fce4d8d2d44150825d8f5f14853e1b06e9226cdf8ac0",
            "The name of the file should match",
        )
        # Test a file with null hash and with a hash value with a lenght smaller than 5 characters, it shouldn't add it in the hashes dict
        sample = self.builder.summary["files"]["file_2"]
        self.builder.create_file(sample)
        stix_result = self.builder.bundle[3]
        self.assertEqual(
            stix_result.hashes.get("imphash"),
            None,
            "The specified key for this hash shouldn't exist in the STIX object",
        )
        self.assertEqual(
            stix_result.hashes.get("ssdeep"),
            None,
            "The specified key for this hash shouldn't exist in the STIX object",
        )

    def test_create_domain(self):
        """
        Test create_domain function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        stix_expected = DomainName(
            type="domain-name",
            value="www.documentcloud.org",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        sample = self.builder.summary["domains"]["domain_0"]
        self.builder.create_domain(sample)
        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Run tests
        assert isinstance(
            stix_result, DomainName
        ), "Return type should be stix2.v21.observables.DomainName"
        self.assertEqual(
            len(self.builder.bundle), 1, "The bundle's length should be equal to 1"
        )
        self.assertEqual(
            stix_expected.value, stix_result.value, "The value should match"
        )
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should match"
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        # Test invalid domain-name
        with self.assertRaises(ValueError):
            self.builder.create_domain({"domain": ""})
        with self.assertRaises(ValueError):
            self.builder.create_domain({"domain": "www"})
        with self.assertRaises(ValueError):
            self.builder.create_domain({"domain": "http"})
        with self.assertRaises(ValueError):
            self.builder.create_domain({"domain": "https"})
        with self.assertRaises(ValueError):
            self.builder.create_domain({"domain": None})
        with self.assertRaises(ValueError):
            sample_invalid = self.builder.summary["domains"]["domain_3"]
            self.builder.create_domain(sample_invalid)
        # Test blacklisted domain
        sample_blacklisted = self.builder.summary["domains"]["domain_2"]
        self.assertIsNone(self.builder.create_domain(sample_blacklisted))

    def test_create_url(self):
        """
        Test create_url function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        # Expected object
        stix_expected = URL(
            value="https://www.documentcloud.org/documents/6497959-Boeing-Text-Messages.html",
            type="url",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        sample = self.builder.summary["urls"]["url_0"]
        self.builder.create_url(sample)
        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Run tests
        assert isinstance(
            stix_result, URL
        ), "Return type should be stix2.v21.observables.URL"
        self.assertEqual(
            len(self.builder.bundle), 1, "The bundle's length should be equal to 1"
        )
        self.assertEqual(
            stix_expected.value, stix_result.value, "The value should match"
        )
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should match"
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        # Test invalid url
        with self.assertRaises(ValueError):
            sample_invalid = self.builder.summary["urls"]["url_2"]
            self.builder.create_url(sample_invalid)

    def test_create_email_address(self):
        """
        Test create_email_address function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        # Expected object
        stix_expected = EmailAddress(
            value="michel@fondu.ch",
            type="email-addr",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        sample = self.builder.summary["email_addresses"]["email_address_2"]
        self.builder.create_email_address(sample)
        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Run tests
        assert isinstance(
            stix_result, EmailAddress
        ), "Return type should be stix2.v21.observables.EmailAddress"
        self.assertEqual(
            len(self.builder.bundle), 1, "The bundle's length should be equal to 1"
        )
        self.assertEqual(
            stix_expected.value, stix_result.value, "The value should match"
        )
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should match"
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )

    def test_create_ip(self):
        """
        Test create_ip function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        # Expected object
        stix_expected = IPv4Address(
            value="45.249.245.35",
            type="ipv4-addr",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        sample = self.builder.summary["ip_addresses"]["ip_address_0"]
        self.builder.create_ip(sample)
        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Run tests
        assert isinstance(
            stix_result, IPv4Address
        ), "Return type should be stix2.v21.observables.URL"
        self.assertEqual(
            len(self.builder.bundle), 1, "The bundle's length should be equal to 1"
        )
        self.assertEqual(
            stix_expected.value, stix_result.value, "The value should match"
        )
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should match"
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        # Test invalid IP
        with self.assertRaises(ValueError):
            sample_invalid = self.builder.summary["ip_addresses"]["ip_address_2"]
            self.builder.create_ip(sample_invalid)

    def test_create_openctitext(self):
        """
        Test create_openctitext function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        # Expected object
        stix_expected = OpenCtiText(
            value='{"office": {"Test01": "TestValue01", "Test02": "TestValue02"}, "pe": {"basic_info": {"Test00": "TestValue00"}}}',
            object_marking_refs=[
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
            ],
            custom_properties=self.custom_props,
        )
        data = self.builder.summary.get("static_data").get("static_data_0")
        self.builder.create_xopenctitext(data)
        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Convert "value" key to dict for testing purpose
        stix_expected_value = json.loads(stix_expected.value)
        stix_result_value = json.loads(stix_result.value)
        # Run tests
        assert isinstance(stix_result, OpenCtiText), "Return type should be OpenCtiText"
        self.assertDictEqual(
            stix_expected_value, stix_result_value, "The value should match"
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        # Test create_xopenctitext with empty value
        self.assertEqual(
            self.builder.create_xopenctitext({"office": {}, "pe": None}), None
        )

    def test_create_report(self):
        """
        Test create_report function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        self.builder.object_refs = []
        # Fill up the bundle
        self.builder.create_file(self.builder.summary["files"]["file_0"])
        self.builder.create_file(self.builder.summary["files"]["file_1"])
        self.builder.create_domain(self.builder.summary["domains"]["domain_0"])
        self.builder.create_domain(self.builder.summary["domains"]["domain_1"])
        # Add object refs
        object_refs = [ref.target for ref in self.builder.object_refs] + [self.builder.sample_id]
        # Expected object
        stix_expected = Report(
            type="report",
            spec_version="2.1",
            description="TestDescription00,TestDescription01,TestDescription02",
            labels={
                "TestValue00",
                "TestValue01",
                "TestValue02",
                "TestValue03",
                "TestValue04",
            },
            created="2022-04-29T15:49:39.974524Z",
            modified="2022-04-29T15:49:39.974524Z",
            name="VMRay analysis ID 813371635",
            report_types=["malware"],
            published="2022-04-27T11:58:31Z",
            object_refs=object_refs,
            confidence=80,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        # Create the report
        self.builder.create_report()
        # Retrieve the result in the bundle (last index)
        stix_result = self.builder.bundle[-1]

        # Run tests
        assert isinstance(
            stix_result, Report
        ), "Return type should be stix2.v21.observables.Report"
        self.assertEqual(
            len(self.builder.bundle), 5, "The bundle's length should be equal to 5"
        )
        self.assertEqual(
            stix_expected.type, stix_result.type, "Type property should be report"
        )
        self.assertEqual(
            len(object_refs),
            4,
            "Object refs length should be equal to 4"
        )
        self.assertEqual(
            len(stix_expected.object_refs),
            len(stix_result.object_refs),
            "Object_ref's lenght should match",
        )
        self.assertCountEqual(
            stix_expected.description.split(","),
            stix_result.description.split(","),
            "Description should be extracted from vti field correctly",
        )
        self.assertCountEqual(
            stix_expected.labels, stix_result.labels, "Labels should be equals"
        )
        self.assertEqual(
            stix_expected.name, stix_result.name, "VMRay analysis ID should match"
        )
        self.assertEqual(
            stix_expected.published,
            stix_result.published,
            "Published date should be equal",
        )
        self.assertEqual(
            stix_expected.report_types,
            stix_result.report_types,
            "Report types should be equal",
        )
        self.assertEqual(
            stix_expected.spec_version,
            stix_result.spec_version,
            "Spec_version property should be 2.1",
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.confidence,
            stix_result.confidence,
            "confidence level property should be equal to stix_expected custom_properties",
        )
        # Test with an empty description
        base_summary = self.builder.summary
        # Remove all description
        for key in self.builder.summary["vti"]["matches"]:
            del self.builder.summary["vti"]["matches"][key]["operation_desc"]
        # Create a report
        self.builder.create_report()
        # Retrieve the result in the bundle (last index)
        stix_result = self.builder.bundle[-1]
        # Key "description" should not exist anymore in the STIX Report
        assert "description" not in stix_result
        self.assertCountEqual(
            stix_expected.labels, stix_result.labels, "Labels should be equals"
        )
        # Set the default summary again
        self.builder.summary = base_summary

    def test_create_relationship(self):
        """
        Test create_relationship function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        self.builder.object_refs = []
        # Fill up the bundle
        self.builder.create_file(self.builder.summary["files"]["file_0"])
        self.builder.create_file(self.builder.summary["files"]["file_1"])
        self.builder.create_domain(self.builder.summary["domains"]["domain_0"])
        self.builder.create_domain(self.builder.summary["domains"]["domain_1"])
        # Create relationships
        for ref in self.builder.object_refs:
            # Ref must be different than root sample (circulare dependency)
            self.builder.create_relationship(ref)
        # Check for relationships number
        counter = len([i for i in self.builder.bundle if i["type"] == "relationship"])
        self.assertEqual(counter, 3, "Relationships number should match 3")

    def test_create_bundle(self):
        """
        Test create_bundle function, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        # Fill up the bundle
        self.builder.create_file(self.builder.summary["files"]["file_0"])
        self.builder.create_file(self.builder.summary["files"]["file_1"])
        self.builder.create_domain(self.builder.summary["domains"]["domain_0"])
        self.builder.create_domain(self.builder.summary["domains"]["domain_1"])
        self.builder.create_xopenctitext(
            self.builder.summary.get("static_data").get("static_data_0")
        )
        # Create relationship
        for ref in self.builder.object_refs:
            self.builder.create_relationship(ref)
        # Generate a report
        self.builder.create_report()
        # Create the bundle
        bundle = self.builder.create_bundle()

        # Run tests
        assert isinstance(bundle, Bundle), "Return type should be a bundle"
        self.assertEqual(
            len(bundle.objects), 12, "The bundle's length should be equal to 10"
        )
        # Count object by type and compare according to the expected value
        stix_expected = {
            "identity": 0,
            "marking-definition": 0,
            "file": 0,
            "domain-name": 0,
            "x-opencti-text": 0,
            "relationship": 0,
            "report": 0,
        }
        for stix in bundle.objects:
            stix_expected[stix["type"]] += 1
        self.assertDictEqual(
            stix_expected,
            {
                "identity": 1,
                "marking-definition": 1,
                "file": 2,
                "domain-name": 2,
                "x-opencti-text": 1,
                "relationship": 4,
                "report": 1,
            },
        )

    def test_create_yara(self):
        """
        Test create_yara_indicator, the result should be equal to the stix_expected variable's field
        """
        self.builder.bundle = []
        self.builder.object_refs = []

        stix_expected = Indicator(
            type="indicator",
            created_by_ref="identity--36ac23e3-47ad-4612-af7a-bc32d134ac5e",
            created="2022-05-02T11:33:07.673324Z",
            modified="2022-05-02T11:33:07.673324Z",
            name="HKTL_CobaltStrike_Loaders_May21_1_RID332A",
            description="Detects unknown maldoc dropper noticed in October 2020. (Ruleset | name: Valhalla, id: 15)",
            pattern='import "pe"\n\nrule HKTL_CobaltStrike_Loaders_May21_1_RID332A : EXE FILE HKTL S0154 T1075\n{\n\tmeta:\n\t\tdescription = "Detects CobaltStrike loaders used in Conti Ransomware campaign"\n\t\tauthor = "Florian Roth"\n\t\treference = "https://www.ncsc.gov.ie/pdfs/HSE_Conti_140521_UPDATE.pdf"\n\t\tdate = "2021-05-18 14:31:41"\n\t\tscore = 90\n\t\tcustomer = "CH150253"\n\t\tlicense = "Distribution to third parties is not permitted and will be pursued with legal measurements"\n\t\thash1 = "1429190cf3b36dae7e439b4314fe160e435ea42c0f3e6f45f8a0a33e1e12258f"\n\t\thash2 = "8837868b6279df6a700b3931c31e4542a47f7476f50484bdf907450a8d8e9408"\n\t\ttags = "EXE, FILE, HKTL, S0154, T1075"\n\t\tminimum_yara = "1.7"\n\t\tclassifications = "HKTL_CobaltStrike_Loaders_May21_1_RID332A, EXE, FILE, HKTL, S0154, T1075"\n\t\tvti_default_score = 4\n\t\tvti_documents_score = 4\n\t\tvti_scripts_score = 4\n\t\tvti_browser_score = 4\n\t\tvti_msi_score = 4\n\t\tvti_static_score = 4\n\n\tstrings:\n\t\t$op1 = { 74 10 31 c9 e8 ?? fe ff ff 31 c9 ff 15 ?? 9? 04 00 90 48 83 c4 28 c3 }\n\t\t$op2 = { 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 04 00 00 00 c7 44 24 20 01 00 00 00 ff 15 ?? 9b 04 00 85 c0 74 3? 48 8b 84 24 ?? 0? 00 00 }\n\n\tcondition:\n\t\tuint16(0)==0x5a4d and filesize <2000KB and all of them\n}\n',
            pattern_type="yara",
            valid_from="2022-04-27T11:58:31Z",
            confidence=80,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        # Ingest full indicators exemple
        with open("ressources/yara.json", "r", encoding="utf-8") as f:
            yara_rule = json.load(f)

        # Create the indicator
        for key in self.builder.summary.get("yara")["matches"]:
            description = self.builder.summary.get("yara")["matches"][key]["description"]
            ruleset_name = self.builder.summary.get("yara")["matches"][key][
                "ruleset_name"
            ]
            ruleset_id = self.builder.summary.get("yara")["matches"][key]["ruleset_id"]

            self.builder.create_yara_indicator(
                ruleset_id,
                ruleset_name,
                description,
                yara_rule,
            )

        # Create relationships for yara
        for ref in self.builder.object_refs:
            # Create STIX Relationship
            self.builder.create_relationship(ref)

        # Retrieve the result in the bundle
        stix_result = self.builder.bundle[0]
        # Run tests
        self.assertEqual(
            stix_expected.pattern_type,
            stix_result.pattern_type,
            "Indicators type should be equal",
        )
        self.assertEqual(
            stix_expected.valid_from, stix_result.valid_from, "Validity should match"
        )
        self.assertEqual(
            stix_expected.description,
            stix_result.description,
            "Description should match",
        )
        self.assertEqual(stix_expected.name, stix_result.name, "Name should match")
        self.assertEqual(
            stix_expected.pattern, stix_result.pattern, "Pattern should match"
        )
        self.assertEqual(
            stix_expected.pattern_type,
            stix_result.pattern_type,
            "Pattern type should match",
        )
        self.assertEqual(
            stix_expected.valid_from,
            stix_result.valid_from,
            "Valid from date should match",
        )
        self.assertListEqual(
            stix_expected.object_marking_refs,
            stix_result.object_marking_refs,
            "object_marking_refs property should be equal to stix_expected object_marking_refs",
        )
        self.assertEqual(
            stix_expected.x_opencti_created_by_ref,
            stix_result.x_opencti_created_by_ref,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.x_metis_modified_on_s,
            stix_result.x_metis_modified_on_s,
            "custom_properties property should be equal to stix_expected custom_properties",
        )
        self.assertEqual(
            stix_expected.confidence,
            stix_result.confidence,
            "confidence level property should be equal to stix_expected custom_properties",
        )

    def test_get_analysis_date(self):
        """
        Test get_analysis_date, the result should be equal to the stix_expected variable's field
        """
        stix_expected = "2022-04-27T11:58:31Z"
        stix_result = self.builder.get_analysis_date()
        self.assertEqual(stix_expected, stix_result, "Output date should match")

    def test_format_domain(self):
        # Test domain name with https
        to_format = "https://test.com"
        self.assertEqual(
            self.builder.format_domain(to_format),
            "test.com",
            "Output domain-name should be test.com",
        )
        # Test domain name with http
        to_format = "http://test.com"
        self.assertEqual(
            self.builder.format_domain(to_format),
            "test.com",
            "Output domain-name should be test.com",
        )
        # Test domain name with https://www
        to_format = "https://test.com"
        self.assertEqual(
            self.builder.format_domain(to_format),
            "test.com",
            "Output domain-name should be test.com",
        )
        # Test domain name with http://www
        to_format = "http://test.com"
        self.assertEqual(
            self.builder.format_domain(to_format),
            "test.com",
            "Output domain-name should be test.com",
        )
        # Test domain name with no protocoles should return the same string
        to_format = "test.com"
        self.assertEqual(
            self.builder.format_domain(to_format),
            "test.com",
            "Output domain-name should be test.com",
        )

    @classmethod
    def tearDownClass(cls):
        # Remove report_str.json file
        if Path(cls.report_str).unlink(missing_ok=True):
            os.remove(cls.report_str)


if __name__ == "__main__":
    unittest.main()
