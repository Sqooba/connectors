# pylint: disable=broad-except
# -*- coding: utf-8 -*-
"""VMRay enrichment module."""
from pathlib import Path
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Identity

from .builder import VMRAYBuilder
from .utils.constants import HASHES_TYPE, SCOS_FIELD, EntityType, ErrorMessage
from .utils.es_client import EsClient
from .utils.utils import deep_get
from .utils.yara_fetcher import YaraFetcher


class VMRayConnector:
    """VMRay connector."""

    _DEFAULT_AUTHOR = "VMRay"
    _CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

    def __init__(self, config_path, blacklist_path=None):
        config = (
            yaml.safe_load(open(config_path, encoding="utf-8"))
            if config_path.is_file()
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        elasticsearch_url = get_config_variable(
            "VMRAY_ELASTICSEARCH_URL",
            ["vmray", "elasticsearch_url"],
            config,
        )
        elasticsearch_index = get_config_variable(
            "VMRAY_ELASTICSEARCH_INDEX",
            ["vmray", "elasticsearch_index"],
            config,
        )

        self.run_on_s = get_config_variable(
            "VMRAY_RUN_ON_S",
            ["vmray", "run_on_s"],
            config,
        )

        self.vmray_url = get_config_variable(
            "VMRAY_URL",
            ["vmray", "url"],
            config,
        )

        self.vmray_api_key = get_config_variable(
            "VMRAY_API_KEY",
            ["vmray", "api_key"],
            config,
        )

        self.blacklist_enabled = get_config_variable(
            "BLACKLIST_ENABLED",
            ["vmray", "blacklist_enabled"],
            config,
        )

        if blacklist_path is None:
            blacklist_file_path = Path(
                __file__
            ).parent.parent.resolve() / get_config_variable(
                "BLACKLIST_FILE",
                ["vmray", "blacklist_file"],
                config,
            )
        else:
            blacklist_file_path = blacklist_path

        self.blacklist_scos = (
            yaml.safe_load(open(blacklist_file_path, encoding="utf-8"))
            if blacklist_file_path.is_file()
            else {}
        )

        self.author = Identity(
            name=self._DEFAULT_AUTHOR,
            identity_class="system",
            description="VMRay is the most comprehensive and accurate solution for automated"
            " detection and analysis of advanced threats. The VMRay Platform offers unparalleled"
            " evasion resistance, noise-free reporting and scalability by combining reputation"
            " and static analysis with groundbreaking sandbox technology.",
            confidence=self.helper.connect_confidence_level,
        )

        # If the blacklist feature is enabled, check the backlist file's integrity
        if self.blacklist_enabled and not self.blacklist_scos:
            raise ValueError("Blacklist file is empty")

        # Open ES & Yara connections
        self.client = EsClient(endpoint=elasticsearch_url, index=elasticsearch_index)
        self.yara_fetcher = YaraFetcher(self.helper, self.vmray_url, self.vmray_api_key)

        self.helper.metric.state("idle")

    def _process_file(self, stix_file):

        # Extract SHA256 from File object
        sha = next(
            filter(
                lambda obs: obs["algorithm"] == HASHES_TYPE.get("SHA_256"),
                stix_file["hashes"],
            ),
            None,
        )

        # If SHA found in the stixfile
        if sha and sha.get("hash"):

            # Retrieve entity_type
            entity_type = EntityType(stix_file["entity_type"])

            # Query ES
            self.helper.log_info(f"Retrieve entity with hash : {sha.get('hash')}")
            res = self.client.search(sha.get("hash"), entity_type)

            # If the query returns at least one entity
            if res["hits"]["total"]["value"] > 0:
                self.helper.log_info(
                    f"Number of hit(s): {res['hits']['total']['value']}"
                )

                # Retrieve data from matches
                matches = [(i["_source"]) for i in res["hits"]["hits"]]

                # Count entity attached to the current bundle
                attached_counter = 0

                # Loop over each match
                for analysis in matches:
                    try:
                        # Initialize builder object
                        builder = VMRAYBuilder(
                            self.author,
                            self.run_on_s,
                            analysis,
                            self.helper,
                            (self.blacklist_enabled, self.blacklist_scos),
                        )
                    except (KeyError, TypeError) as ex:
                        self.helper.metric.inc("client_error_count")
                        self.helper.log_info(
                            f"{ErrorMessage.INIT_ERROR.format('VMRay', 'builder')} : {ex}"
                        )
                        continue
                    except Exception as ex:
                        self.helper.metric.inc("client_error_count")
                        self.helper.log_info(
                            f"{ErrorMessage.INIT_ERROR.format('VMRay', 'builder')} : {ex}"
                        )
                        continue

                    # =============== Process analysis ================= #

                    # Process SCOs
                    for sco in [
                        s for s in SCOS_FIELD.values() if s["key"] in builder.summary
                    ]:
                        for key in builder.summary.get(sco["key"]):
                            try:
                                # Control if the current item is not the sample
                                if builder.sample and builder.sample[0] == key:
                                    self.helper.log_info(
                                        f"You're processing the sample ({key}), skipping"
                                    )
                                    continue
                                # Create STIX SCO
                                getattr(builder, sco["transform"])(
                                    builder.summary[sco["key"]][key]
                                )
                            except Exception as ex:
                                self.helper.metric.inc("client_error_count")
                                self.helper.log_error(
                                    f"{ErrorMessage.STIX_ERROR.format('VMRay', sco['key'])} : {ex}"
                                )

                    # Create Yara rule
                    if "matches" in builder.summary.get("yara"):
                        yara_matches = deep_get(builder.summary, "yara", "matches")
                        for key in yara_matches:
                            yara_data = deep_get(builder.summary, "yara", "matches")[
                                key
                            ]
                            # Access yara name and id if not None
                            if (
                                yara_data.get("rule_name") is not None
                                and yara_data.get("ruleset_id") is not None
                            ):
                                # Retrieve yara rule
                                yara_rule = self.yara_fetcher.get_yara_rule(
                                    yara_data.get("ruleset_id"),
                                    yara_data.get("rule_name"),
                                )
                                self.helper.log_debug(f"YARA_RULE: {yara_rule}")

                            else:
                                self.helper.log_error(
                                    "[VMRay] A key is missing (name or id) in the yara match "
                                    f"({yara_data}), skipping"
                                )
                                continue

                            ruleset_name = yara_data.get("ruleset_name")
                            ruleset_id = yara_data.get("ruleset_id")
                            description = yara_data.get("description", "Unknown")
                            try:
                                # Create STIX Indicator
                                builder.create_yara_indicator(
                                    ruleset_id, ruleset_name, description, yara_rule
                                )
                            except Exception as ex:
                                self.helper.metric.inc("client_error_count")
                                self.helper.log_error(
                                    f"{ErrorMessage.STIX_ERROR.format('VMRay', 'Yara Indicator')} : {ex}"
                                )

                    # Process open-cti-text
                    if "static_data" in builder.summary:
                        for cti_text in builder.summary.get("static_data"):
                            builder.create_text(
                                builder.summary.get("static_data").get(cti_text)
                            )
                    else:
                        self.helper.log_warning(
                            "[VMRay] Field 'static_data' not found in summary,"
                            " cannot generate xopenctitext"
                        )

                    # Create relationships
                    for ref in builder.relationships:
                        try:
                            # Create STIX Relationship
                            builder.create_relationship(ref)
                        except Exception as ex:
                            self.helper.metric.inc("client_error_count")
                            self.helper.log_debug(ref)
                            self.helper.log_error(
                                f"{ErrorMessage.STIX_ERROR.format('VMRay', 'Relationship')} : {ex}"
                            )

                    try:
                        # Create STIX Report
                        builder.create_report(stix_file["standard_id"])
                    except Exception as ex:
                        self.helper.metric.inc("client_error_count")
                        self.helper.log_error(
                            f"{ErrorMessage.STIX_ERROR.format('VMRay', 'Report')} : {ex}"
                        )
                        # Report mandatory, jump to the next iteration
                        continue

                    try:
                        # Create STIX Bundle
                        bundle = builder.create_bundle()
                    except Exception as ex:
                        self.helper.metric.inc("client_error_count")
                        self.helper.log_error(
                            f"{ErrorMessage.STIX_ERROR.format('VMRay', 'Bundle')} : {ex}"
                        )
                        # Bundle mandatory, Jump to the next iteration
                        continue

                    try:
                        # Serialize and send the Bundle
                        self.helper.log_info(
                            f"Sending a bundle with : {len(bundle.objects)} entities"
                        )
                        attached_counter += len(bundle.objects)
                        self.helper.metric.inc("record_send", 1 + len(bundle.objects))
                        self.helper.send_stix2_bundle(bundle.serialize())
                    except ValueError as ex:
                        self.helper.metric.inc("client_error_count")
                        self.helper.log_error(
                            f"{ErrorMessage.SEND_BUNDLE.format('VMRay')} : {ex}"
                        )
                    except Exception as ex:
                        self.helper.metric.inc("client_error_count")
                        self.helper.log_error(
                            f"{ErrorMessage.UNKNOW.format('VMRay', 'sending the bundle')} : {ex}"
                        )

                if attached_counter > 0:
                    # Notify OpenCti that the result has been sent
                    self.helper.log_info(
                        "Process is done, bundle has been sent successfully"
                    )
                    return f"Observable found on VMRay, {attached_counter} knowledge attached."

                # No attachment found
                self.helper.log_info("All bundles were empty, no attachment to send")
                raise ValueError("Sample type not supported.")

        # No data founded on ES
        self.helper.log_info(f"[VMRay] no result for stixfile with SHA : {sha}")
        raise ValueError(ErrorMessage.ES_NOT_FOUND.format("VMRay"))

    def _process_message(self, data):
        # Get entity ID send by OpenCti enrichment connector
        entity_id = data["entity_id"]
        # Retrieve full sample from the API
        stix_file = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Process Data
        return self._process_file(stix_file)

    def start(self) -> None:
        """
        Start to listen, pass process_message as a callback
        """
        # Start the main loop
        self.helper.listen(self._process_message)
