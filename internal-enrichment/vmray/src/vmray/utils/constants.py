# -*- coding: utf-8 -*-
"""Constants for VMRay Connector."""

from enum import Enum


class ErrorMessage:
    """This class allow error message centralization"""

    INVALID_VALUE = "[{}] - Value '{}' is not valid, operation aborted"
    INIT_ERROR = "[{}] - An error occurred during the {} initialization"
    STIX_ERROR = "[{}] - An error occurred while generating STIX entity of type {}"
    YARA_PARSING = "[{}] An error occurred while trying to parse the yara rules"
    SEND_BUNDLE = "[{}] - An error occurred while sending the Bundle to the API"
    UNKNOW = "[{}] - An unknown error occurred while {}"
    ES_NOT_FOUND = (
        "[{}] - Analysis not found on ElasticSearch throught VMRay enrichment connector"
    )
    ROOT_SAMPLE_NOT_FOUND = "[{}] - Root sample not found, operation aborted"
    WRONG_ANALYSIS = "[{}] - The analysis sent to the builder is inconsistent"
    POORLY_TYPED_ANALYSED = """[{}] - The analysis sent to the builder does not respect the mandatory types,
                            field 'sample_details' must be of type dict and field 'summary' of type str"""
    ANALYSIS_METADATA_NOT_FOUND = "[{}] - 'analysis_metadata' not found in the analysis, report generation aborted"


class InfoMessage:
    """This class allow info message centralization"""

    SAMPLE_TYPE_FOUND = (
        "[{}] - Sample of type {} found in the analysis_metadata field, processing .."
    )
    SAMPLE_TYPE_NOT_FOUND = """[{}] - Analysis type could not be determined (analysisId: {}),
                            this information is mandatory in order to build relationships."""
    CREATE_EMAIL_ADDR = "[{}] - An email address will be created with value : {}"
    ANALYSIS_DATE_NOT_FOUND = (
        "[{}] - Field offsetDateTime not found, using current date"
    )
    ANALYSIS_DATE_FOUND = "[{}] - Field offsetDateTime found, setting value {}"
    BLACKLISTED_VALUE = "[{}] - Value '{}' is blacklisted, operation aborted"
    VERDICT_FOUND = "[{}] - verdict found with value {}"


class EntityType(Enum):
    """Enumeration of possible entities."""

    STIXFILE = "StixFile"
    DOMAIN_NAME = "domain-name"
    EMAIL_ADDR = "email-addr"
    EMAIL_MESSAGE = "email-message"
    FILE = "file"
    IPV4_ADDR = "ipv4-addr"
    URL = "url"
    REPORT = "report"
    RELATIONSHIP = "relationship"
    INDICATOR = "indicator"
    BUNDLE = "bundle"


class RelationshipType(Enum):
    """Enumeration of possible relationships type."""

    RELATED = "related-to"
    RESOLVES = "resolves-to"


# Be careful, the order matters
SCOS_FIELD = {
    "DOMAIN": {"key": "domains", "transform": "create_domain", "sample": False},
    "EMAIL-ADDRESS": {
        "key": "email_addresses",
        "transform": "create_email_address",
        "sample": False,
    },
    "IP": {"key": "ip_addresses", "transform": "create_ip", "sample": False},
    "FILE": {"key": "files", "transform": "create_file", "sample": True},
    "URL": {"key": "urls", "transform": "create_url", "sample": True},
    "EMAIL-MESSAGE": {
        "key": "emails",
        "transform": "create_email_message",
        "sample": True,
    },
}

HASHES_TYPE = {
    "MD5": "MD5",
    "SHA_1": "SHA-1",
    "SHA_256": "SHA-256",
    "SHA_512": "SHA-512",
    "SHA3_256": "SHA3-256",
    "SHA3_512": "SHA3-512",
    "SSDEEP": "SSDEEP",
}

SAMPLE_TYPE = {
    "FILE": {EntityType.FILE.value: SCOS_FIELD["FILE"]},
    "URL": {EntityType.URL.value: SCOS_FIELD["URL"]},
    "EMAIL (EML)": {EntityType.EMAIL_MESSAGE.value: SCOS_FIELD["EMAIL-MESSAGE"]},
    "EMAIL (MSG)": {EntityType.EMAIL_MESSAGE.value: SCOS_FIELD["EMAIL-MESSAGE"]},
}

VERDICTS = {"clean": 10, "suspicious": 80, "malicious": 100}

STATIC_DATA_FIELD = {"office", "pe", "pdf"}

INVALID_DOMAIN = {"www", "http", "https"}

CUSTOM_FIELDS = {
    "CREATED_BY_REF": "x_opencti_created_by_ref",
    "SCORE": "x_opencti_score",
}
