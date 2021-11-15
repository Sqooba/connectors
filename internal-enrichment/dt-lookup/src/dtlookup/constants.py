# -*- coding: utf-8 -*-
"""Constants for DT-Lookup."""

from enum import Enum


class EntityType(Enum):
    """Enumeration of possible entities."""

    AUTONOMOUS_SYSTEM = "Autonomous-System"
    DOMAIN_NAME = "Domain-Name"
    EMAIL_ADDRESS = "Email-Addr"
    IPV4 = "IPv4-Addr"


CONTACTS_TYPE = {
    "a": "admin",
    "b": "billing",
    "r": "registrant",
    "t": "technical",
}

DOMAINS_FIELD = {
    "ns": "name-server",
    "mx": "mx-server",
}

EMAILS_FIELD = {
    "em": "email",
    "ema": "DNS/SOA",
    "emw": "whois",
    "empa": "email-admin",
    "empb": "email-billing",
    "empr": "email-registrant",
    "empt": "email-technical",
}

BLACKLIST = {"REDACTED FOR PRIVACY"}
