# -*- coding: utf-8 -*-
"""Alerting builder module."""
import datetime
import sys
from typing import Optional

import stix2
import vt
from pycti import Incident, OpenCTIConnectorHelper, StixCoreRelationship


class AlertingBuilder:
    """Alerting builder."""

    _SOURCE = "fingerprint_alerting"
    # Observable type to retrieve with corresponding route on VirusTotal.
    _ENTITY_TYPES = {
        "Domain-Name": "domains",
        "IPv4-Addr": "ip_addresses",
    }
    # Name to use in the URL for VirusTotal reference.
    _BASE_URL = {
        "Domain-Name": "domain",
        "IPv4-Addr": "ip-address",
    }

    # Name of the VirusTotal relationship to retrieve communicating files.
    _VT_RELATIONSHIP = "communicating_files"

    def __init__(
        self,
        client: vt.Client,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        author_name: str,
        label: str,
        exclude: str,
        last_n_days: int,
        first_submission_n_days: int,
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.author_name = author_name
        self.label = label
        self.exclude = exclude
        self.bundle = []
        self.last_n_days = last_n_days
        self.first_submission_n_days = first_submission_n_days

        label_obj = self.helper.api.label.read(
            filters=[{"key": "value", "values": label}]
        )
        if not label_obj:
            self.helper.log_error(f"Label {label} does not exist, exiting")
            sys.exit(1)

        self.label_id = label_obj["id"]

        exclude_obj = self.helper.api.label.read(
            filters=[{"key": "value", "values": exclude}]
        )
        if not exclude_obj:
            self.helper.log_error(f"Label to exclude {exclude} does not exist, exiting")
            sys.exit(1)

        self.exlucde_id = exclude_obj["id"]

    def get_reports_with_label(self, start_date: datetime.datetime):
        # Attributes to return
        custom_attributes = """
                id
                standard_id
                published
                objects {
                    edges {
                        node {
                          ... on BasicObject {
                            id
                            entity_type
                            parent_types
                          }
                        }
                    }
                }
            """

        data = {"pagination": {"hasNextPage": True, "endCursor": None}}
        while data["pagination"]["hasNextPage"]:
            after = data["pagination"]["endCursor"]
            self.helper.log_debug(f"Listing reports after {after}")
            data = self.helper.api.report.list(
                first=100,
                after=after,
                customAttributes=custom_attributes,
                filters=[
                    {
                        "key": "published",
                        "values": [str(int(start_date.timestamp()))],
                        "operator": "gt",
                    },
                    {"key": "labelledBy", "values": self.label_id, "operator": "eq"},
                    {
                        "key": "labelledBy",
                        "values": self.exlucde_id,
                        "operator": "not_eq",
                    },
                ],
                orderBy="published",
                orderMode="asc",
                withPagination=True,
            )
            self.helper.log_debug(f"Data retrieved: {data}")
            yield from data["entities"]

    def process(self):
        start_date_reports = datetime.datetime.now() - datetime.timedelta(
            days=self.last_n_days
        )
        start_date_file = datetime.datetime.now() - datetime.timedelta(
            days=self.first_submission_n_days
        )
        self.helper.log_info(
            f"Retrieving MISP IoCs published after {start_date_reports}"
        )

        for report in self.get_reports_with_label(start_date_reports):
            self.helper.log_debug(f"Report retrieved: {report}")
            for obj in report["objects"]:
                if obj.get("entity_type", "") not in self._ENTITY_TYPES:
                    self.helper.log_debug(f"Not processing observable {obj}")
                    continue

                observable = (
                    self.helper.api.opencti_stix_object_or_stix_relationship.read(
                        id=obj["id"]
                    )
                )
                try:
                    url = f'/{self._ENTITY_TYPES[observable["entity_type"]]}/{observable["observable_value"]}/{self._VT_RELATIONSHIP}'
                    self.helper.log_debug(f"Url to VirusTotal: {url}")
                    files_iterator = self.client.iterator(url, limit=100)
                    recent_files = [
                        i
                        for i in files_iterator
                        if i.first_submission_date > start_date_file
                    ]
                    if len(recent_files) > 0:
                        self.helper.log_info(
                            f"Observable {observable} found on VirusTotal, creating alert"
                        )
                        self.create_alert(observable, recent_files, report["standard_id"])
                    else:
                        self.helper.log_debug(
                            f"Observable {observable} haven't communicate with recent files"
                        )
                except vt.error.APIError as e:
                    self.helper.log_debug(
                        f"Observable {observable} not found on VirusTotal, err={e}"
                    )

    def create_alert(self, observable, vtobjs, report_id):
        """
        Create the alert

        Parameters
        ----------
        observable
            Observable from the report.
        vtobjs
            Virustotal recent files.
        report_id
            Id of the fingerprint report that triggered the alert.
        """
        name = f'[{self.label}] Alert from observable {observable["observable_value"]}'
        alert = self.helper.api.incident.read(filters=[{"key": "name", "values": name}])
        if alert:
            self.helper.log_debug(f"Alert {name} already exists, skipping")
            return
        # Create external reference to Virustotal report
        external_reference = self.create_external_reference(
            f'https://www.virustotal.com/gui/{self._BASE_URL[observable["entity_type"]]}/{observable["observable_value"]}',
            "Virustotal Analysis",
        )
        # Create the alert
        incident = stix2.Incident(
            id=Incident.generate_id(name, datetime.datetime.now()),
            incident_type="alert",
            name=name,
            description=f'Fingerprint alert for {observable["observable_value"]}',
            source=self._SOURCE,
            created_by_ref=self.author["standard_id"],
            confidence=self.helper.connect_confidence_level,
            labels=self.label_id,
            external_references=[external_reference],
            allow_custom=True,
        )
        self.bundle.append(incident)
        # Create the relationship to the observable
        rel_to_observable = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                incident["id"],
                observable["standard_id"],
            ),
            relationship_type="related-to",
            created_by_ref=self.author["standard_id"],
            source_ref=incident["id"],
            target_ref=observable["standard_id"],
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle.append(rel_to_observable)

        # Create the relationship to the recent communicating files from VirusTotal.
        for vtobj in vtobjs:
            self.create_file(vtobj, incident["id"])

        # Create the relationship to the report
        rel_to_report = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                incident["id"],
                report_id,
            ),
            relationship_type="related-to",
            created_by_ref=self.author["standard_id"],
            source_ref=incident["id"],
            target_ref=report_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle.append(rel_to_report)

    def create_file(self, vtobj, incident_id: Optional[str] = None) -> str:
        """
        Create a file and link it to the created incident, if any.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.

        Returns
        -------
        str
            Id of the created file.
        """
        self.helper.log_debug(f"Adding file from VirusTotal {vtobj}")
        score = None
        try:
            if hasattr(vtobj, "last_analysis_stats"):
                score = self._compute_score(vtobj.last_analysis_stats)
        except ZeroDivisionError as e:
            self.helper.log_error(f"Unable to compute score of file, err = {e}")

        external_reference = self.create_external_reference(
            f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
            "Virustotal Analysis",
        )

        file = stix2.File(
            type="file",
            name=f'{vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else "unknown"}',
            hashes={
                "MD5": vtobj.md5,
                "SHA256": vtobj.sha256,
                "SHA1": vtobj.sha1,
            },
            size=vtobj.size,
            external_references=[external_reference],
            custom_properties={
                "x_opencti_score": score,
                "created_by_ref": self.author["standard_id"],
            },
            allow_custom=True,
        )
        self.bundle.append(file)
        # Link to the incident if any.
        if incident_id is not None:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    incident_id,
                    file["id"],
                ),
                relationship_type="related-to",
                created_by_ref=self.author["standard_id"],
                source_ref=incident_id,
                target_ref=file["id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle.append(relationship)
        return file["id"]

    def create_external_reference(self, url: str, description: str):
        """
        Create an external reference.

        Used to have a link to the file on VirusTotal.

        Parameters
        ----------
        url : str
            Url for the external reference.
        description : str
            Description fot the external reference.

        Returns
        -------
        stix2.ExternalReference
            The external reference object.
        """
        external_reference = stix2.ExternalReference(
            source_name=self.author_name,
            url=url,
            description=description,
            custom_properties={
                "created_by_ref": self.author["standard_id"],
            },
        )
        return external_reference

    def send_bundle(self, work_id: str):
        """
        Send the bundle to OpenCTI.

        After being sent, the bundle is reset.

        Parameters
        ----------
        work_id : str
            Work id to use
        """
        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
        self.helper.log_debug(f"Sending bundle: {bundle}")
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        # Reset the bundle for the next import.
        self.bundle = []

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError as e:
            raise ValueError(
                "Cannot compute score. VirusTotal may have no record of the observable"
            ) from e
        return vt_score
