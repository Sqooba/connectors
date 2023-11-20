# -*- coding: utf-8 -*-
"""IncidentEnricher enrichment module."""
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import stix2
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable


@dataclass
class Enricher:
    name: str
    id: str
    types: list[str]


class IncidentEnricherConnector:
    """IncidentEnricher connector."""

    _SOURCE_NAME = "IncidentEnricher"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)

        self.author = stix2.Identity(
            id=Identity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="IncidentEnricher",
            confidence=self.helper.connect_confidence_level,
        )

        self.enrichers_config = get_config_variable(
            "ENRICHER_CONNECTORS",
            ["enricher", "connectors"],
            config,
        )

        available_connectors = self.helper.api.connector.list()

        self.enricher_by_types = {}

        for connector in self.enrichers_config:
            connector_id = get_connector_id(available_connectors, connector["name"])
            if not connector_id:
                self.helper.log_error(f"Error retrieving connector ID for {connector}")
                continue

            enricher = Enricher(
                id=connector_id, name=connector["name"], types=connector["types"]
            )

            for t in enricher.types:
                if t not in self.enricher_by_types:
                    self.enricher_by_types[t] = []
                self.enricher_by_types[t] += [enricher]

        self.helper.log_info(
            f"Enrichment connectors retrieved by types: {self.enricher_by_types}"
        )

    def _process_message(self, data):
        self.helper.log_debug(f"Starting enrichment with data received: {data}")
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        # Retrieve all details of the incident.
        incident = self.helper.api.incident.read(id=data["entity_id"])
        self.helper.log_debug(f"Incident read: {incident}")
        if incident is None:
            return "Error reading incident"

        # We need to make two queries, one using the incident in the `to` field
        # and one using it in the `from` field depending on how the objects were linked.
        custom_attributes_from = """
            id
            from {
               ... on Incident {
                   id
                   name
               }
            }
            to {
                ... on StixCyberObservable {
                    id
                    entity_type
                    observable_value
                }
            }
        """
        rels_from_incident = self.helper.api.stix_core_relationship.list(
            fromId=incident["id"],
            toTypes=list(self.enricher_by_types.keys()),
            customAttributes=custom_attributes_from,
        )
        self.helper.log_debug(
            f"Relationships from incident retrieved: {rels_from_incident}"
        )
        observables = [i["to"] for i in rels_from_incident]

        custom_attributes_to = """
            id
            from {
                ... on StixCyberObservable {
                    id
                    entity_type
                    observable_value
                }
            }
            to {
               ... on Incident {
                   id
                   name
               }
            }
        """
        rels_to_incident = self.helper.api.stix_core_relationship.list(
            toId=incident["id"],
            fromTypes=list(self.enricher_by_types.keys()),
            customAttributes=custom_attributes_to,
        )
        self.helper.log_debug(
            f"Relationships from incident retrieved: {rels_to_incident}"
        )
        observables += [i["from"] for i in rels_to_incident]

        self.helper.log_debug(f"Observables retrieved: {observables}")
        if not observables:
            return "No observable to enrich"

        result = f"Enriching {len(observables)} observables\n"

        with_error = False

        # Enrich each observable with their corresponding enrichment connector.
        # This is based on the type of the observable.
        for obs in observables:
            self.helper.log_info(f"Enriching observable: {obs}")
            for enricher in self.enricher_by_types[obs["entity_type"]]:
                self.helper.log_info(f"Triggering enricher: {enricher}")

                work_id = self.helper.api.stix_cyber_observable.ask_for_enrichment(
                    id=obs["id"],
                    connector_id=enricher.id,
                )
                # Wait for connector to finish
                status = self.wait_for_work_to_finish(work_id, max_retry=10)
                if status != "":
                    with_error = True
                    result += f'{obs["observable_value"]} -> {status}\n'

        self.helper.log_debug(result)

        self.helper.metric.state("idle")
        if with_error:
            raise ValueError(result)
        return result

    def wait_for_work_to_finish(self, work_id: str, max_retry: int = 10):
        """
        Wait for work to finish but with a maximal number of retries.

        There is a wait period of 1 second between each retry.

        Parameters
        ----------
        work_id : str
            Work id to check
        max_retry : int, default 10
            Maximal number of retry because exiting

        Returns
        -------
        str
            An empty string if it completed successfully, an error message if any,
            or a timeout exceeded in case of max retry reached.
        """
        status = ""
        cnt = 0
        while status != "complete":
            state = self.helper.api.work.get_work(work_id=work_id)
            if len(state) > 0:
                status = state["status"]

                if state["errors"]:
                    self.helper.log_error(
                        f"Unexpected connector error {state['errors']}"
                    )
                    return state["errors"]

            time.sleep(1)
            cnt += 1
            if cnt >= max_retry:
                self.helper.log_info("Max retry exceeded, stop waiting for connector")
                return "Unable to get response from connector"
        return ""

    def start(self):
        """Start the main loop."""
        self.helper.metric.state("idle")
        self.helper.listen(self._process_message)


def get_connector_id(all_connectors, name: str) -> Optional[str]:
    for connector in all_connectors:
        if connector["name"] in name:
            return connector["id"]
    return None
