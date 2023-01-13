# -*- coding: utf-8 -*-
"""VMRay connector test file."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

import pytest
from stix2 import (
    TLP_AMBER,
    URL,
    Bundle,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    Identity,
    Indicator,
    IPv4Address,
    Relationship,
    Report,
)

sys.path.append("..")
from src.vmray.builder import VMRAYBuilder
from src.vmray.models.text import Text
from src.vmray.utils.constants import EntityType, RelationshipType


class TestBuilder:
    """
    This class is use to test the VMRayBuilder class.

    A file named report_dict.json must be created in the tests/ressources directory. Unlike the analysed report, the
    summary key in the report_dict.json must be of type dict. This allow the tester to change according to his needs the
    content of the summary.

    The file is then converted into the same format as the one sent by ES and used by the builder. This file gets removed after the tests.
    """

    @classmethod
    def setup_class(cls):
        # Init input file PATH
        cls._FILE_REPORT_IN = "ressources/report_dict_file.json"
        cls._EMAIL_REPORT_IN = "ressources/report_dict_email.json"
        cls._URL_REPORT_IN = "ressources/report_dict_url.json"
        cls._NONE_REPORT_IN = "ressources/report_dict_none.json"
        # Init output file PATH
        cls._FILE_REPORT_OUT = "ressources/report_str_file.json"
        cls._EMAIL_REPORT_OUT = "ressources/report_str_email.json"
        cls._URL_REPORT_OUT = "ressources/report_str_url.json"
        cls._NONE_REPORT_OUT = "ressources/report_str_none.json"
        # Init input Yara rules file
        cls._YARA_RULES = "ressources/yara.json"

        # Mock helper OpenCtiConnector
        cls.helper = MagicMock()
        cls.confidence_level = PropertyMock(return_value=80)
        type(cls.helper).connect_confidence_level = cls.confidence_level

        # Setup author
        cls.author = Identity(
            name="VMRay",
            identity_class="system",
            description="Test description",
            confidence=80,
        )

        # Initialize custom properties
        cls.custom_props = {
            "x_opencti_created_by_ref": cls.author["id"],
        }

    @pytest.fixture
    def file_analysis(self):
        return TestBuilder.generate_analysis(
            self._FILE_REPORT_IN, self._FILE_REPORT_OUT
        )

    @pytest.fixture
    def mail_analysis(self):
        return TestBuilder.generate_analysis(
            self._EMAIL_REPORT_IN, self._EMAIL_REPORT_OUT
        )

    @pytest.fixture
    def url_analysis(self):
        return TestBuilder.generate_analysis(self._URL_REPORT_IN, self._URL_REPORT_OUT)

    @pytest.fixture
    def none_analysis(self):
        return TestBuilder.generate_analysis(
            self._NONE_REPORT_IN, self._NONE_REPORT_OUT
        )

    @pytest.mark.parametrize(
        "analysis, expected",
        [
            ("file_analysis", ["file", 1, 0]),
            ("mail_analysis", ["email-message", 6, 2]),
            ("url_analysis", ["url", 1, 0]),
            ("none_analysis", [None, 0, 0]),
        ],
    )
    def test_get_sample(self, analysis, expected, request):
        """
        Test the get_sample function, in order to test every possibility, multiple analysis are loaded.
        """
        builder = VMRAYBuilder(
            self.author, False, request.getfixturevalue(analysis), self.helper
        )
        # Run tests
        assert len(builder.bundle) == expected[1]
        assert len(builder.relationships) == expected[2]
        if expected[0]:
            assert builder.sample[1].id.split("--")[0] == expected[0]
        else:
            assert not builder.sample

    @pytest.mark.parametrize(
        "analysis, expected",
        [
            ("", TypeError),
            ({}, KeyError),
            ({"sample_details": {"test": "test"}, "summary": {}}, TypeError),
            ({"sample_details": 2, "summary": "test"}, TypeError),
            ({"sample_details": {}, "summary": ""}, KeyError),
        ],
    )
    def test_init_builder(self, analysis, expected):
        """
        Test to initialize the builder with wrong values
        """
        # Initialize a builder with inconsistent analysis should throw an error
        with pytest.raises(expected):
            VMRAYBuilder(self.author, False, analysis, self.helper)

    def test_create_file(self, file_analysis):
        """
        Test create_file function, the result should be equal to the expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = File(
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
            custom_properties={**self.custom_props, **{"x_opencti_score": 10}},
        )
        # Pass the file to the create function and retrieve it from the bundle
        builder.create_file(builder.summary["files"]["file_0"])
        result = builder.bundle[0]
        # Run tests
        assert len(builder.bundle) == 1, "The bundle's length should be equal to 1"
        assert (
            expected.hashes == result.hashes
        ), "Hashes property should be equal to expected hashes"
        assert expected.name == result.name, "The name of the file should match"
        self.default_test(expected, result)
        # Test the name of file_1, it should set the filename_1's key name
        builder.create_file(builder.summary["files"]["file_1"])
        result = builder.bundle[1]
        # Run tests
        assert result.name == "testName.exe", "The name of the file should match"
        # Test the name of a file with no name value, it should take the hash-256
        builder.create_file(builder.summary["files"]["file_2"])
        result = builder.bundle[2]
        assert (
            result.name
            == "7ae0ec1732c1e565e532fce4d8d2d44150825d8f5f14853e1b06e9226cdf8ac0"
        ), "The name of the file should match"
        # Test a file with null hash and with a hash value with a length smaller than 5 characters,
        assert (
            result.hashes.get("imphash") is None
        ), "The hashe value of the file should match"
        assert (
            result.hashes.get("ssdeep") is None
        ), "The hashe value of the file should match"
        # Test the score of the file_0, should be set to 10 (clean)
        assert (
            result.x_opencti_score is expected.x_opencti_score
        ), "The score should match"

    def test_create_domain(self, file_analysis):
        """
        Test create_domain function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = DomainName(
            type="domain-name",
            value="www.documentcloud.org",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties={**self.custom_props, **{"x_opencti_score": 10}},
        )
        # Pass the domain to the create function and retrieve it from the bundle
        builder.create_domain(builder.summary["domains"]["domain_0"])
        result = builder.bundle[1]
        # Run tests
        assert len(builder.bundle) == 2, "The bundle's length should be equal to 2"
        assert expected.value == result.value, "The value of the domain should match"
        self.default_test(expected, result)

        with pytest.raises(ValueError):
            builder.create_domain({"domain": ""})
        with pytest.raises(ValueError):
            builder.create_domain({"domain": "www"})
        with pytest.raises(ValueError):
            builder.create_domain({"domain": "http"})
        with pytest.raises(ValueError):
            builder.create_domain({"domain": "https"})
        with pytest.raises(ValueError):
            builder.create_domain({"domain": None})
        with pytest.raises(ValueError):
            builder.create_domain({"domain": "https"})
        with pytest.raises(ValueError):
            sample_invalid = builder.summary["domains"]["domain_3"]
            builder.create_domain(sample_invalid)
        # Test blacklisted domain
        assert (
            builder.create_domain(builder.summary["domains"]["domain_2"]) is None
        ), "Blacklisted domain should resturn None"
        # Test the score of the domain_0, should be set to 10 (clean)
        assert (
            result.x_opencti_score is expected.x_opencti_score
        ), "The score should match"

    def test_create_url(self, file_analysis):
        """
        Test create_url function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = URL(
            value="https://www.documentcloud.org/documents/6497959-Boeing-Text-Messages.html",
            type="url",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties={**self.custom_props, **{"x_opencti_score": 80}},
        )
        # Pass the url to the create function and retrieve it from the bundle
        builder.create_url(builder.summary["urls"]["url_0"])
        result = builder.bundle[1]
        # Run tests
        assert len(builder.bundle) == 2, "The bundle's length should be equal to 2"
        assert expected.value == result.value, "The value of the url should match"
        self.default_test(expected, result)
        # Test invalid url
        with pytest.raises(ValueError):
            sample_invalid = builder.summary["urls"]["url_2"]
            builder.create_url(sample_invalid)
        # Test the score of the url_0, should be set to 80 (malicious)
        assert (
            result.x_opencti_score is expected.x_opencti_score
        ), "The score should match"

    def test_create_email_address(self, file_analysis):
        """
        Test create_email_address function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = EmailAddress(
            value="michel@fondu.ch",
            type="email-addr",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties={**self.custom_props, **{"x_opencti_score": 100}},
        )
        # Pass the email address to the create function and retrieve it from the bundle
        builder.create_email_address(
            builder.summary["email_addresses"]["email_address_2"]
        )
        result = builder.bundle[1]
        # Run tests
        assert len(builder.bundle) == 2, "The bundle's length should be equal to 2"
        assert (
            expected.value == result.value
        ), "The value of the email_address should match"
        self.default_test(expected, result)
        # Test an invalid email-address
        with pytest.raises(ValueError):
            sample_invalid = builder.summary["email_addresses"]["email_address_3"]
            builder.create_email_address(sample_invalid)
        # Test to create an email address already in the bundle
        address_bundle = builder.create_email_address(
            builder.summary["email_addresses"]["email_address_2"]
        )
        assert (
            result.id == address_bundle
        ), "Email address id should match, this entity has already been push in the bundle"
        # Test the score of the email_address_2, should be set to 10 (clean)
        assert (
            result.x_opencti_score is expected.x_opencti_score
        ), "The score should match"

    def test_create_email_message(self, file_analysis):
        """
        Test create_email_message function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = EmailMessage(
            type="email-message",
            spec_version="2.1",
            is_multipart=True,
            object_marking_refs=TLP_AMBER,
            custom_properties={**self.custom_props, **{"x_opencti_score": 10}},
        )
        # Pass the email-message to the create function and retrieve it from the bundle
        builder.create_email_message(builder.summary["emails"]["email_0"])
        result = builder.bundle[-1]
        # Retrieve the sender
        expected_sender = builder.get_from_bundle(
            "email-addr", "vadim_melnik88@i.ua", "value"
        )
        # Retrieve recipients
        expected_recipients = []
        expected_recipients.extend(
            [
                builder.get_from_bundle("email-addr", "usbu_dnp@ssu.gov.ua", "value"),
                builder.get_from_bundle("email-addr", "michel@fondu.ch", "value"),
            ]
        )
        # Run tests
        assert (
            len(builder.relationships) == 6
        ), "The relationships array's length should be equal to 6"
        assert len(builder.bundle) == 6, "The bundle's length should be equal to 6"
        assert expected.is_multipart is True, "is_multipart property should match"
        self.default_test(expected, result)
        assert (
            expected_sender.id == result.from_ref
        ), "The sender should be equal to stix_result value"
        assert len(expected_recipients) == 2, "The recipient's length should be 2"
        assert [
            x.id for x in expected_recipients
        ] == result.to_refs, "Recipients property should match"
        # Test the score of the email_address_2, should be set to 10 (clean)
        assert (
            result.x_opencti_score is expected.x_opencti_score
        ), "The score should match"

    def test_create_ip(self, file_analysis):
        """
        Test create_ip function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = IPv4Address(
            type="ipv4-addr",
            value="45.249.245.35",
            spec_version="2.1",
            object_marking_refs=TLP_AMBER,
            custom_properties={**self.custom_props, **{"x_opencti_score": 10}},
        )
        # Pass the IPv4 address to the create function and retrieve it from the bundle
        builder.create_ip(builder.summary["ip_addresses"]["ip_address_0"])
        result = builder.bundle[1]
        # Run tests
        assert len(builder.bundle) == 2, "The bundle's length should be equal to 2"
        assert expected.value == result.value, "The value of the url should match"
        self.default_test(expected, result)
        # Test invalid IP
        with pytest.raises(ValueError):
            builder.create_ip(builder.summary["ip_addresses"]["ip_address_2"])
        # Test to create a resolve-to between an ip-addr and a domain
        builder.create_domain(builder.summary["domains"]["domain_0"])
        domain = builder.bundle[2]
        builder.create_ip(builder.summary["ip_addresses"]["ip_address_1"])
        ip_addr = builder.bundle[3]
        # A resolve-to relationship should exist in the relationship array
        relation = next(
            x
            for x in builder.relationships
            if x.relationship_type == RelationshipType.RESOLVES.value
        )
        assert relation is not None, "Relation should not be None"
        assert (
            relation.source == domain.id
        ), "Relation source and domain id should match"
        assert (
            relation.target == ip_addr.id
        ), "Relation target and ip_addr id should match"
        # Create the relationships
        for rel in builder.relationships:
            builder.create_relationship(rel)
        # Test the relationships stix object from the bundle
        relation = [
            x
            for x in builder.bundle
            if x.type == "relationship"
            and x.relationship_type == RelationshipType.RESOLVES.value
        ]
        assert relation is not None, "Relation should not be None"
        # Test the score of the email_address_2, should be set to 10 (clean)
        assert (
            result.x_opencti_score is expected.x_opencti_score
        ), "The score should match"

    def test_create_text(self, file_analysis):
        """
        Test create_text function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = Text(
            value='{"office": {"Test01": "TestValue01", "Test02": "TestValue02"}, "pe": {"basic_info": {"Test00": "TestValue00"}}}',
            object_marking_refs=[
                "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
            ],
            custom_properties=self.custom_props,
        )
        # Pass the text object to the create function and retrieve it from the bundle
        builder.create_text(builder.summary.get("static_data").get("static_data_0"))
        result = builder.bundle[1]
        # Run tests
        assert len(builder.bundle) == 2, "The bundle's length should be equal to 2"
        assert json.loads(expected.value) == json.loads(
            result.value
        ), "The value of the raw text should match"
        self.default_test(expected, result)
        # Test create_text with empty value
        assert (
            builder.create_text({"office": {}, "pe": None}) is None
        ), "Wrong values passed to Text should return None"

    def test_create_yara(self, file_analysis):
        """
        Test create_yara_indicator, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Expected object
        expected = Indicator(
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
        with open(self._YARA_RULES, "r", encoding="utf-8") as file:
            yara_rule = json.load(file)
        # Create the indicator
        for key in builder.summary.get("yara")["matches"]:
            description = builder.summary.get("yara")["matches"][key]["description"]
            ruleset_name = builder.summary.get("yara")["matches"][key]["ruleset_name"]
            ruleset_id = builder.summary.get("yara")["matches"][key]["ruleset_id"]
            # For each match, generate a Stix Indicator
            builder.create_yara_indicator(
                ruleset_id,
                ruleset_name,
                description,
                yara_rule,
            )
        # Retrieve the result in the bundle
        result = builder.bundle[1]
        # Run tests
        assert len(builder.bundle) == 3, "The bundle's length should be equal to 3"
        assert (
            expected.valid_from == result.valid_from
        ), "valid_from property should match"
        assert (
            expected.description == result.description
        ), "description property should match"
        assert expected.name == result.name, "name property should match"
        assert expected.pattern == result.pattern, "pattern property should match"
        assert (
            expected.pattern_type == result.pattern_type
        ), "pattern_type property should match"
        assert (
            expected.confidence == result.confidence
        ), "confidence property should match"
        self.default_test(expected, result)

    def test_create_relationship(self, file_analysis, mail_analysis):
        """
        Test create_relationship function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Fill up the bundle
        builder.create_file(builder.summary["files"]["file_1"])
        builder.create_domain(builder.summary["domains"]["domain_0"])
        builder.create_domain(builder.summary["domains"]["domain_1"])
        # Create relationships
        for ref in builder.relationships:
            builder.create_relationship(ref)
        # Test each relation
        relationships = [x for x in builder.bundle if x.type == "relationship"]
        for relation in relationships:
            assert isinstance(
                relation, Relationship
            ), "Return type should be a relationship"
            assert (
                "VMRay: sample to IOC" == relation.description
            ), "Description property should match"
            assert (
                builder.sample[1].id == relation.source_ref
            ), "source_ref property should match"
            assert (
                RelationshipType.RELATED.value == relation.relationship_type
            ), "relationship_type should match"
        # Check for relationships number
        assert len(relationships) == 3, "Relationships number should match 3"
        # Create a new builder with an email analysis
        fake_builder = VMRAYBuilder(self.author, False, mail_analysis, self.helper)
        # Fill up the bundle
        fake_builder.create_domain(fake_builder.summary["domains"]["domain_0"])
        fake_builder.create_domain(fake_builder.summary["domains"]["domain_1"])
        fake_builder.create_file(fake_builder.summary["files"]["file_1"])
        fake_builder.create_file(fake_builder.summary["files"]["file_2"])
        for x in range(0, 5):
            try:
                fake_builder.create_email_address(
                    fake_builder.summary["email_addresses"][f"email_address_{x}"]
                )
            except:
                continue
        # Create relationships
        for ref in fake_builder.relationships:
            fake_builder.create_relationship(ref)
        # Test each relation
        relationships = [x for x in fake_builder.bundle if x.type == "relationship"]
        for relation in relationships:
            assert isinstance(
                relation, Relationship
            ), "Return type should be a relationship"
            assert (
                fake_builder.sample[1].id == relation.source_ref
            ), "source_ref property should match"
            assert (
                RelationshipType.RELATED.value == relation.relationship_type
            ), "relationship_type should match"
            if "file--" in relation.description:
                # The relationships between the email message and the attachements(files) should have a different description
                assert (
                    "Email attachment" == relationships[3].description
                ), "Description should match"
                assert (
                    "Email attachment" == relationships[4].description
                ), "Description should match"
        # Check for relationships number
        assert len(relationships) == 8, "Relationships number should match 8"

    def test_create_report(self, file_analysis, none_analysis):
        """
        Test create_report function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Fill up the bundle
        for x in range(0, 2):
            builder.create_file(builder.summary["files"][f"file_{x}"])
            builder.create_domain(builder.summary["domains"][f"domain_{x}"])
        for x in range(0, 3):
            builder.create_email_address(
                builder.summary["email_addresses"][f"email_address_{x}"]
            )
        # Expected object
        expected = Report(
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
            object_refs=builder.object_refs,
            confidence=80,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        # Create the report
        builder.create_report()
        # Retrieve the result in the bundle (last index)
        result = builder.bundle[-1]
        # Run tests
        assert len(builder.bundle) == 8, "The bundle's length should be equal to 1"
        assert (
            expected.confidence == result.confidence
        ), "confidence property should match"
        assert len(expected.object_refs) == 7, "Object refs length should be equal to 7"
        assert len(expected.object_refs) == len(
            result.object_refs
        ), "Object_ref's lenght should match"
        assert set(expected.description) == set(
            result.description
        ), "Description should be extracted from vti field correctly"
        assert len(expected.labels) == len(result.labels)
        assert set(expected.labels) == set(result.labels)
        # assert expected.labels == result.labels, "Labels should be equals"
        assert expected.name == result.name, "VMRay analysis ID should match"
        assert expected.published == result.published, "Published date should be equal"
        assert (
            expected.report_types == result.report_types
        ), "Report types should be equal"
        self.default_test(expected, result)
        # Remove all description and labels
        del builder.summary["classifications"]
        for key in builder.summary["vti"]["matches"]:
            del builder.summary["vti"]["matches"][key]["operation_desc"]
            del builder.summary["vti"]["matches"][key]["category_desc"]
        # Create a report
        builder.create_report()
        # Retrieve the result in the bundle (last index)
        result = builder.bundle[-1]
        # Key "description" should not exist anymore in the STIX Report
        assert (
            "description" not in result
        ), "Description should not exist in description property"
        assert (
            result.get("labels") is None
        ), "Labels should not exist in labels property"
        # Test that even without a sample ID the builder can work and generate a consistent report
        builder_no_smpl = VMRAYBuilder(self.author, False, none_analysis, self.helper)
        # Fill up the bundle
        builder_no_smpl.create_file(builder_no_smpl.summary["files"]["file_0"])
        builder_no_smpl.create_file(builder_no_smpl.summary["files"]["file_1"])
        builder_no_smpl.create_domain(builder_no_smpl.summary["domains"]["domain_0"])
        builder_no_smpl.create_domain(builder_no_smpl.summary["domains"]["domain_1"])
        for x in range(0, 3):
            builder_no_smpl.create_email_address(
                builder_no_smpl.summary["email_addresses"][f"email_address_{x}"]
            )
        builder_no_smpl.create_report()
        report = builder_no_smpl.bundle[-1]
        # Relationships class attribut should be empty
        assert not builder_no_smpl.relationships, "Relationship array should be empty"
        # Report's object_refs should contain ids
        assert len(report.object_refs) == 7, "Object refs length should be equal to 7"

    def test_create_bundle(self, file_analysis):
        """
        Test create_bundle function, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Fill up the bundle
        builder.create_file(builder.summary["files"]["file_1"])
        builder.create_domain(builder.summary["domains"]["domain_0"])
        builder.create_domain(builder.summary["domains"]["domain_1"])
        builder.create_text(builder.summary.get("static_data").get("static_data_0"))
        # Create relationship
        for ref in builder.relationships:
            builder.create_relationship(ref)
        # Generate a report
        builder.create_report()
        # Create the bundle
        bundle = builder.create_bundle()
        # Run tests
        assert isinstance(bundle, Bundle), "Return type should be a bundle"
        assert len(bundle.objects) == 12, "The bundle's length should be equal to 12"
        # Count object by type and compare according to the expected value
        stix_expected = {
            "identity": 0,
            "marking-definition": 0,
            "file": 0,
            "domain-name": 0,
            "text": 0,
            "relationship": 0,
            "report": 0,
        }
        for stix in bundle.objects:
            stix_expected[stix["type"]] += 1

        assert stix_expected == {
            "identity": 1,
            "marking-definition": 1,
            "file": 2,
            "domain-name": 2,
            "text": 1,
            "relationship": 4,
            "report": 1,
        }, "stix_expected should match"

    def test_get_analysis_date(self, file_analysis):
        """
        Test get_analysis_date, the result should be equal to the stix_expected variable's field
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        expected = "2022-04-27T11:58:31Z"
        result = builder.get_analysis_date()
        assert expected == result, "Output date should match"

    def test_get_from_bundle(self, file_analysis):
        """
        Test get_from_bundle function, the result should be equal to the stix_expected entities
        """
        builder = VMRAYBuilder(self.author, False, file_analysis, self.helper)
        # Fill up the bundle
        builder.create_file(builder.summary["files"]["file_0"])
        builder.create_file(builder.summary["files"]["file_1"])
        builder.create_domain(builder.summary["domains"]["domain_0"])
        builder.create_domain(builder.summary["domains"]["domain_1"])
        # Get expected result from the bundle
        file_expected_00 = builder.bundle[0]
        file_expected_01 = builder.bundle[1]
        domain_expected_00 = builder.bundle[2]
        domain_expected_01 = builder.bundle[3]
        # Compare with retrieve result from the get_from_bundle function
        assert file_expected_00 == builder.get_from_bundle(
            "file", file_expected_00.id, "id"
        )
        assert file_expected_01 == builder.get_from_bundle(
            "file", file_expected_01.id, "id"
        )
        assert domain_expected_00 == builder.get_from_bundle(
            "domain-name", domain_expected_00.id, "id"
        )
        assert domain_expected_01 == builder.get_from_bundle(
            "domain-name", domain_expected_01.id, "id"
        )

    def test_duplicate_process(self, mail_analysis):
        """
        In some cases, entities are processed twice, we want to make sure we don't have
        duplicate in the relationships
        """
        builder = VMRAYBuilder(self.author, False, mail_analysis, self.helper)
        # At this point, the bundle should contains some entities
        assert 6 == len(builder.bundle)
        assert 1 == len(
            [
                obj
                for obj in builder.bundle
                if obj.type == EntityType.EMAIL_MESSAGE.value
            ]
        )
        assert 2 == len(
            [obj for obj in builder.bundle if obj.type == EntityType.FILE.value]
        )
        assert 3 == len(
            [obj for obj in builder.bundle if obj.type == EntityType.EMAIL_ADDR.value]
        )
        # The relationship should not have been process for email-address
        assert 2 == len(builder.relationships)
        # Process the email_addresses in the summary
        for x in range(0, 3):
            builder.create_email_address(
                builder.summary["email_addresses"][f"email_address_{x}"]
            )
        assert 5 == len(builder.relationships)
        assert 3 == len(
            [
                rel
                for rel in builder.relationships
                if EntityType.EMAIL_ADDR.value in rel.target
            ]
        )

    @classmethod
    def teardown_class(cls):
        # Remove generated string reports
        if Path(cls._FILE_REPORT_OUT).unlink(missing_ok=True):
            os.remove(cls._FILE_REPORT_OUT)
        if Path(cls._EMAIL_REPORT_OUT).unlink(missing_ok=True):
            os.remove(cls._EMAIL_REPORT_OUT)
        if Path(cls._URL_REPORT_OUT).unlink(missing_ok=True):
            os.remove(cls._URL_REPORT_OUT)
        if Path(cls._NONE_REPORT_OUT).unlink(missing_ok=True):
            os.remove(cls._NONE_REPORT_OUT)

    @staticmethod
    def default_test(expected, result):
        assert isinstance(
            result, type(expected)
        ), f"Return type should be a {type(expected)}"
        assert expected.type == result.type, "type property should match"
        assert (
            expected.spec_version == result.spec_version
        ), "spec_version property should match"
        assert (
            result.x_opencti_created_by_ref == expected.x_opencti_created_by_ref
        ), "x_opencti_created_by_ref property should match"
        assert (
            expected.object_marking_refs == result.object_marking_refs
        ), "object_marking_refs property should match"

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
