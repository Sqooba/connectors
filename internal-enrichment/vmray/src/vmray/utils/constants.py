# -*- coding: utf-8 -*-
"""Constants for VMRay Connector."""

from enum import Enum


class ErrorMessage:
    """This class allow error message centralization"""

    INVALID_VALUE = "[{}] - Value '{}' is not valid, operation aborted"
    INIT_ERROR = "[{}] - An error occurred during the {} initialization"
    STIX_ERROR = "[{}] - An error occurred while generating STIX entity of type {}"
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

STATIC_DATA_FIELD = {"office", "pe", "pdf"}

INVALID_DOMAIN = {"www", "http", "https"}

BLACKLIST_DOMAIN = {
    "mbkw.myonlineportal.net",
    "hkgqt.my-homeip.net",
    "xlew.my-homeip.de",
    "bzpt.my-homeip.net",
    "ttch.my-homeip.de",
    "kvzu.my-homeip.de",
    "qvxrz.myonlineportal.net",
    "nfxg.my-homeip.net",
    "static.xx.fbcdn.net",
    "assets.adobedtm.com",
    "ukhf.my-homeip.de",
    "yuliqa.my-homeip.net",
    "wcam.my-homeip.net",
    "ghhpym.my-homeip.net",
    "dpm.demdex.net",
    "js-agent.newrelic.com",
    "meta.wikimedia.org",
    "en.wikipedia.org",
    "geolocation.onetrust.com",
    "fonts.gstatic.com",
    "securepubads.g.doubleclick.net",
    "instagram.com",
    "cdn.cookielaw.org",
    "deref-mail.com",
    "mc.yandex.ru",
    "code.jquery.com",
    "maxcdn.bootstrapcdn.com",
    "files-migrate.r53.acrobat.com",
    "files-legacy-fc.adobe.io",
    "files.acrobat.com",
    "twitter.com",
    "pagead2.googlesyndication.com",
    "cewzu.shock-srv.com",
    "123dd.shock-srv.com",
    "cveer.join-shockbyte.com",
    "nedsaq.shock-srv.com",
    "linkedin.com",
    "upload.wikimedia.org",
    "37a89.ramshard.net",
    "awess.shock-srv.com",
    "ajax.googleapis.com",
    "login.wikimedia.org",
    "ospwysmierzyce.pl",
    "cdnjs.cloudflare.com",
    "google.com",
    "connect.facebook.net",
    "youtube.com",
    "google-analytics.com",
    "facebook.com",
    "fonts.googleapis.com",
    "googletagmanager.com",
    "bartlomiejbotta.pl",
    "polskilink.com.pl",
    "cbdbypanda.pl",
}
