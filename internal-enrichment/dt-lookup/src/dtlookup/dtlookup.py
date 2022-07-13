# -*- coding: utf-8 -*-
"""DT-Lookup enrichment module."""

from pathlib import Path

import json
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity
import validators
import yaml

from .builder import DtBuilder
from .client import EsClient
from .constants import (
    EntityType,
    CONTACTS_TYPE,
    DOMAINS_FIELD,
    EMAILS_FIELD,
    BLACKLIST,
)


class DTLookupConnector:
    """DT-Lookup connector."""

    _DEFAULT_AUTHOR = "DomainTools"
    _CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        elasticsearch_url = get_config_variable(
            "DTLOOKUP_ELASTICSEARCH_URL",
            ["dtlookup", "elasticsearch_url"],
            config,
        )
        elasticsearch_index = get_config_variable(
            "DTLOOKUP_ELASTICSEARCH_INDEX",
            ["dtlookup", "elasticsearch_index"],
            config,
        )

        self.run_on_s = get_config_variable(
            "DTLOOKUP_RUN_ON_S",
            ["dtlookup", "run_on_s"],
            config,
        )

        self.author = Identity(
            name=self._DEFAULT_AUTHOR,
            identity_class="organization",
            description=" DomainTools is a leading provider of Whois and other DNS"
            " profile data for threat intelligence enrichment."
            " It is a part of the Datacenter Group (DCL Group SA)."
            " DomainTools data helps security analysts investigate malicious"
            " activity on their networks.",
            confidence=self.helper.connect_confidence_level,
        )

        self.client = EsClient(endpoint=elasticsearch_url, index=elasticsearch_index)
        self.helper.metric.state("idle")

    def _process_file(self, observable):
        entity_type = EntityType(observable["entity_type"])
        res = self.client.search(observable["observable_value"], entity_type)

        if res["hits"]["total"]["value"] > 0:
            self.helper.metric.state("running")
            self.helper.metric.inc("run_count")

            matches = [json.loads(i["_source"]["raw"]) for i in res["hits"]["hits"]]
            for raw in matches:
                builder = DtBuilder(
                    self.helper, self.author, raw.get("cr"), self.run_on_s
                )
                # Name Servers (ns / mx)
                for category, description in DOMAINS_FIELD.items():
                    for domains in raw.get(category, ()):
                        if (server := domains.get(category)) != observable[
                            "observable_value"
                        ]:
                            if not validators.domain(server):
                                self.helper.metric.inc("error_count")
                                self.helper.log_warning(
                                    f"[DomainTools] domain {server} is not correctly "
                                    "formatted. Skipping."
                                )
                                continue
                            new_domain_id = builder.link_domain_resolves_to(
                                observable["standard_id"],
                                server,
                                EntityType.DOMAIN_NAME,
                                description,
                            )
                            # Add the related ips to the newly created domain.
                            for ip in domains.get(f"{category[:1]}ip", ()):
                                builder.link_domain_resolves_to(
                                    new_domain_id,
                                    ip,
                                    EntityType.IPV4,
                                    f"{description}-ip",
                                )

                # Redirects (red)
                if red := raw.get("red"):
                    if not validators.domain(red):
                        self.helper.metric.inc("error_count")
                        self.helper.log_warning(
                            f"[DomainTools] domain {red} is not correctly formatted. Skipping."
                        )
                        continue
                    builder.link_domain_resolves_to(
                        observable["standard_id"],
                        red,
                        EntityType.DOMAIN_NAME,
                        "redirect",
                    )

                # IP (ip.ip / ip.asn)
                for entry in raw.get("ip", ()):
                    if ip := entry.get("ip"):
                        ip_id = builder.link_domain_resolves_to(
                            observable["standard_id"],
                            ip,
                            EntityType.IPV4,
                            "domain-ip",
                        )
                        for asn in entry.get("asn", ()):
                            builder.link_ip_belongs_to_asn(ip_id, asn)

                # Emails
                for category, description in EMAILS_FIELD.items():
                    for email in raw.get(category, ()):
                        if not validators.email(email):
                            self.helper.metric.inc("error_count")
                            self.helper.log_warning(
                                f"[DomainTools] email {email} is not correctly formatted. Skipping."
                            )
                            continue
                        builder.link_domain_related_to_email(
                            observable["standard_id"], email, description
                        )

                # Domains of emails
                for domain in raw.get("emd", ()):
                    if not validators.domain(domain):
                        self.helper.log_warning(
                            f"[DomainTools] domain {domain} is not correctly formatted. Skipping."
                        )
                        continue
                    builder.link_domain_resolves_to(
                        observable["standard_id"],
                        domain,
                        EntityType.DOMAIN_NAME,
                        "email-domain",
                    )

                # Contacts
                for contact in raw.get("cons", ()):
                    if "nm" in contact or "org" in contact:
                        # Skip if the name or the org is in the blacklist.
                        if (
                            contact.get("nm") in BLACKLIST
                            or contact.get("org") in BLACKLIST
                        ):
                            continue
                        identity_id = builder.create_identity(contact)
                        builder.create_related_to(
                            observable["standard_id"],
                            identity_id,
                            json.dumps([CONTACTS_TYPE[t] for t in contact["t"]]),
                        )

            if len(builder.bundle) > 1:
                builder.send_bundle()
                self.helper.log_info(
                    f"[DomainTools] inserted {len(builder.bundle)} entries."
                )
                self.helper.metric.state("idle")
                return f"Observable found on DomainTools, {len(builder.bundle)} knowledge attached."

        self.helper.metric.state("idle")
        self.helper.log_debug(f"[DomainTools] no result for {observable=}")
        return "Observable not found on DomainTools."

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        return self._process_file(observable)

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
