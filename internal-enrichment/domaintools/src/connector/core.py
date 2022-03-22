# -*- coding: utf-8 -*-
"""DomainTools enrichment module."""

import logging
from datetime import datetime
from pathlib import Path

from pycti import OpenCTIConnectorHelper, get_config_variable
import pytz
from stix2 import DomainName, Identity
import validators
import yaml
import dnsdb2
import domaintools

from .builder import DtBuilder
from .constants import (
    DEFAULT_RISK_SCORE,
    EMAIL_FIELDS,
    EntityType,
)
from .es_manager import ESManager
from .record import Record


class DomainToolsConnector:
    """DomainTools connector."""

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

        # DomainTools
        api_username = get_config_variable(
            "DOMAINTOOLS_API_USERNAME",
            ["domaintools", "api_username"],
            config,
        )
        api_key = get_config_variable(
            "DOMAINTOOLS_API_KEY",
            ["domaintools", "api_key"],
            config,
        )
        self.api = domaintools.API(api_username, api_key)

        # DNSDB
        dnsdb_api_key = get_config_variable(
            "DOMAINTOOLS_DNSDB_API_KEY",
            ["domaintools", "dnsdb_api_key"],
            config,
        )

        # API for ElasticSearch insertion
        self.app_api_base_url = get_config_variable(
            "DOMAINTOOLS_APP_API_BASE_URL",
            ["domaintools", "app_api_base_url"],
            config,
        )
        self.app_sso_base_url = get_config_variable(
            "DOMAINTOOLS_APP_SSO_BASE_URL",
            ["domaintools", "app_sso_base_url"],
            config,
        )
        self.app_kibana_redirect_url = get_config_variable(
            "DOMAINTOOLS_APP_KIBANA_REDIRECT_URL",
            ["domaintools", "app_kibana_redirect_url"],
            config,
        )
        if self.app_kibana_redirect_url[-1] == "/":
            self.app_kibana_redirect_url = self.app_kibana_redirect_url[:-1]
        self.app_realm_name = get_config_variable(
            "DOMAINTOOLS_APP_REALM_NAME",
            ["domaintools", "app_realm_name"],
            config,
        )
        self.app_client_id = get_config_variable(
            "DOMAINTOOLS_APP_CLIENT_ID",
            ["domaintools", "app_client_id"],
            config,
        )
        self.app_user = get_config_variable(
            "DOMAINTOOLS_APP_USER",
            ["domaintools", "app_user"],
            config,
        )
        self.app_password = get_config_variable(
            "DOMAINTOOLS_APP_PASSWORD",
            ["domaintools", "app_password"],
            config,
        )
        self.app_base_path = Path(
            get_config_variable(
                "DOMAINTOOLS_APP_BASE_PATH",
                ["domaintools", "app_base_path"],
                config,
            )
        )

        self.client = dnsdb2.Client(dnsdb_api_key)

        # Check that the account is valid by trying to retrieve account info.
        try:
            _ = self.api.account_information()
        except domaintools.exceptions.NotAuthorizedException as e:
            self.helper.metric_inc("error_count")
            self.helper.log_error(f"Initialization of the API failed: {e}")

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

        self.helper.metric_state("idle")

    def _enrich_domaintools(self, builder: DtBuilder, observable: dict) -> bool:
        """
        Enrich observable using DomainTools API.

        Only enrichment regarding email addresses is done using this API, for
        domain and ip enrichment, see `_enrich_dnsdb`.

        Parameters
        ----------
        builder : DtBuilder
            Builder to enrich the observable and create the bundle.
        observable : dict
            Observable received from OpenCTI.

        Returns
        -------
        bool
            True if the observable has been enriched, otherwise False.
        """
        logging.debug("Starting enrichment using DomainTools API.")

        results = (
            self.api.iris_investigate(observable["observable_value"])
            .response()
            .get("results", ())
        )
        self.helper.metric_state("running")
        self.helper.metric_inc("run_count")

        for entry in results:
            score = entry.get("domain_risk", {}).get("risk_score", DEFAULT_RISK_SCORE)
            # Get the creation date / expiration date for the validity.
            creation_date = datetime.strptime(
                entry.get("create_date", {}).get("value", ""), "%Y-%m-%d"
            )
            expiration_date = datetime.strptime(
                entry.get("expiration_date", {}).get("value", ""), "%Y-%m-%d"
            )

            builder.set_score(score)

            # Emails
            for category, description in EMAIL_FIELDS.items():
                emails = (
                    entry.get(category, ())
                    if "contact" not in category
                    else entry.get(category, {}).get("email", ())
                )
                for email in emails:
                    builder.link_domain_related_to_email(
                        observable["standard_id"],
                        email["value"],
                        creation_date,
                        expiration_date,
                        description,
                    )

            # Redirects (red)
            if (red := entry.get("redirect_domain", {}).get("value", "")) not in (
                observable["observable_value"],
                "",
            ):
                builder.link_domain_resolves_to(
                    observable["standard_id"],
                    red,
                    EntityType.DOMAIN_NAME,
                    creation_date,
                    expiration_date,
                    "redirect",
                )

        if len(builder.bundle) > 1:
            builder.send_bundle()
            self.helper.log_info(
                f"[DomainTools] inserted {len(builder.bundle)} entries."
            )
            self.helper.metric_state("idle")
            return True
        return False

    def _enrich_dnsdb(self, builder: DtBuilder, observable: dict) -> bool:
        """
        Enrich observable using DNSDB API.

        When having multiple entries for the same relationship, takes the first and
        last date ever seen for the relationship.

        Example:
        google.com -> google.ch (start=2021.11.27, end=2021.11.29)
        google.com -> google.ch (start=2022.01.11, end=2022.01.14)

        will give:
        google.com -> google.ch (start=2021.11.27, end=2022.01.14)

        However, all the details are saved directly in ElasticSearch (index `pdns_record-000001`).

        Parameters
        ----------
        builder : DtBuilder
            Builder to enrich the observable and create the bundle.
        observable : dict
            Observable received from OpenCTI.

        Returns
        -------
        bool
            True if the observable has been enriched, otherwise False.
        """
        logging.debug("Starting enrichment using DNSDB API.")
        builder.reset_score()

        if validators.domain(observable["value"]):
            logging.debug(
                f'Retrieving related records of {observable["value"]} using rrset.'
            )
            records = list(
                self.client.lookup_rrset(observable["value"], ignore_limited=True)
            )
        elif validators.ipv4(observable["value"]):
            logging.debug(
                f'Retrieving related records of {observable["value"]} using rdata_ip.'
            )
            records = list(
                self.client.lookup_rdata_ip(observable["value"], ignore_limited=True)
            )
        else:
            logging.warning(
                f"Given observable ({observable}) is neither an ip or a domain."
            )
            return False

        es_manager = ESManager(
            self.app_base_path,
            self.app_api_base_url,
            self.app_sso_base_url,
            self.app_realm_name,
            self.app_client_id,
            self.app_user,
            self.app_password,
        )

        # Dictionary to store all the records to insert.
        # A key contains a tuple (source, destination).
        to_insert: dict[tuple[str, str], Record] = {}

        for i in records:
            logging.debug(f"Processing record {i}.")
            # Some first uses `zone_time_*` instead of `time_*`
            if "zone_time_first" in i and "zone_time_last" in i:
                i["time_first"] = i["zone_time_first"]
                i["time_last"] = i["zone_time_last"]

            # Skip entries having same time_last and time_first.
            if i["time_last"] > i["time_first"]:
                # Extract the source en remove the trailing dot of the domain.
                source = i["rrname"][:-1]
                # Process of the destinations (domains or ips)
                for destination in i["rdata"]:
                    # Remove tailing dot of domain.
                    if destination[-1] == ".":
                        destination = destination[:-1]

                    if source == destination:
                        logging.debug(
                            "Observable to insert is the same as the one being enriched. Skipping."
                        )
                        continue

                    date_first = datetime.fromtimestamp(i["time_first"], tz=pytz.utc)
                    date_last = datetime.fromtimestamp(i["time_last"], tz=pytz.utc)
                    description = f"{date_first} - {date_last} (count={i['count']})"

                    # Store the record to be inserted in ElasticSearch.
                    es_manager.add_to_batch(
                        source, destination, i["rrtype"], date_first, date_last
                    )

                    # If the domain is already present, take the oldest and newest dates
                    # and update the description with the historic.
                    if (source, destination) in to_insert:
                        to_insert[(source, destination)].set_conflict()
                        to_insert[(source, destination)].update_all_time_first(
                            date_first
                        )
                        to_insert[(source, destination)].update_all_time_last(date_last)
                        to_insert[
                            (source, destination)
                        ].description += f"\n\n{description}"
                    else:
                        to_insert[(source, destination)] = Record(
                            source,
                            destination,
                            date_first,
                            date_last,
                            i["rrtype"],
                            description,
                        )

        # Insert all the records (with details) in ElasticSearch.
        es_manager.bulk_insert()
        logging.info("DNSDB records inserted in ElasticSearch.")

        # Create the link to kibana for the current observable.
        if len(to_insert) > 0 and observable["entity_type"] == "Domain-Name":
            description = observable["x_opencti_description"] or ""
            if self.app_kibana_redirect_url not in description:
                description += f"\n\nLink to kibana: {self.app_kibana_redirect_url}/?domain={observable['observable_value']}"
                self.helper.api.stix_cyber_observable.update_field(
                    id=observable["id"],
                    input={"key": "x_opencti_description", "value": description},
                )

        for record in to_insert.values():
            entity_type = record.get_destination_type()

            if entity_type is not None:
                # The observable being enriched can either be a domain-name of an ipv4.
                # In case of an ipv4 being enriched, we need to create the domain-name (source).
                # In case of a domain-name being enriched, we need to create the destination.
                if observable["entity_type"] == "Domain-Name":
                    source_id = observable["standard_id"]
                    destination_id = (
                        builder.create_domain(record.destination)
                        if entity_type == EntityType.DOMAIN_NAME
                        else builder.create_ipv4(record.destination)
                    )
                elif observable["entity_type"] == "IPv4-Addr":
                    destination_id = observable["standard_id"]
                    source_id = builder.create_domain(record.source)
                else:
                    logging.warning(f"Observable {observable} is not valid, skipping.")
                    continue

                if source_id is not None and destination_id is not None:
                    relation = builder.create_resolves_to(
                        source_id,
                        destination_id,
                        record.first_date,
                        record.last_date,
                    )
                    if record.has_conflict:
                        logging.debug(
                            f"Inserting note for record with conflicts: {record}"
                        )
                        builder.create_note(
                            relation,
                            "Details of DNSDB",
                            f"{record.rtype}\n\n{record.description}",
                        )

        return True

    def _process_file(self, observable):
        self.helper.metric_state("running")
        self.helper.metric_inc("run_count")

        builder = DtBuilder(self.helper, self.author)

        # Enrichment using DomainTools API.
        if observable["entity_type"] == "IPv4-Addr":
            if not self._enrich_domaintools(builder, observable):
                logging.warning(
                    f"Observable {observable['value']} not enriched using DomainTools API."
                )

        # Enrichment using DNSDB API.
        if not self._enrich_dnsdb(builder, observable):
            logging.warning(
                f"Observable {observable['value']} not enriched using DNS DB API."
            )

        if len(builder.bundle) > 1:
            builder.send_bundle()
            self.helper.log_info(
                f"[DomainTools] inserted {len(builder.bundle)} entries."
            )
            self.helper.metric_state("idle")

        return f"Observable found on DomainTools, {len(builder.bundle)} knowledge attached."

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        return self._process_file(observable)

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
