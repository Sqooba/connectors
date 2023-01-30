# -*- coding: utf-8 -*-
"""RcAttConnector enrichment module."""
import tempfile
import time
from pathlib import Path
from typing import List, Tuple

import yaml
from pycti import AttackPattern, OpenCTIConnectorHelper, get_config_variable

from .predictions import predict
from .preprocessing import pdf_to_text


class RcAttConnector:
    """
    RcAttConnector

    All operations are done directly using the api and not using stix2 bundles.
    This is needed to avoid unknown references when adding the newly created objects in the initial report.
    """

    _SOURCE_NAME = "rcATT"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.author = self.helper.api.identity.create(
            type="Organization",
            name=self._SOURCE_NAME,
            description="A python app to predict Att&ck tactics and techniques from cyber threat reports",
            confidence=self.helper.connect_confidence_level,
        )

        self.auto = get_config_variable(
            "CONNECTOR_AUTO",
            ["connector", "confidence_auto"],
            config,
            True,
        )
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            True,
        )
        self.link_to_malware = get_config_variable(
            "RCATT_LINK_TO_MALWARE",
            ["rcatt", "link_to_malware"],
            config,
        )
        self.link_to_intrusion_set = get_config_variable(
            "RCATT_LINK_TO_INTRUSION_SET",
            ["rcatt", "link_to_intrusion_set"],
            config,
        )

    def predict_ttps(self, content: bytes):
        """
        Predict Tactics, Techniques and Procedures based on the content of the file.

        Parameters
        ----------
        content
            Content of the file.

        Returns
        -------
        list
            List of ttps predicted.
        """
        # The rcATT predictor needs a file to do the predictions.
        with tempfile.NamedTemporaryFile() as tmp:
            pdf_to_text(content, Path(tmp.name))
            self.helper.log_info(f"Sentences saved to {tmp.name}")
            ttps = predict(tmp.name)
            self.helper.log_info(f"TTPs predicted: {ttps}")
            return ttps

    def _process_message(self, data):
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        self.helper.log_info(data)
        entity_id = data["entity_id"]
        report = self.helper.api.report.read(id=entity_id)
        if report is None:
            raise ValueError(
                "Report not found (or the connector does not have access to this report, "
                "check the group of the connector user)"
            )
        self.helper.log_info(f"report={report}")

        if self.auto and not report["importFiles"]:
            self.helper.log_info("Waiting for potential files to be uploaded.")
            time.sleep(30)

        if not report["importFiles"]:
            raise ValueError("Report does not have any pdf.")

        # A report object can have multiples files, do the predictions for all files.
        ttps = []
        for file in report["importFiles"]:
            content = self.helper.api.fetch_opencti_file(
                f'{self.helper.opencti_url}/storage/get/{file["id"]}', binary=True
            )
            self.helper.log_debug(f"content={content}")

            ttps += self.predict_ttps(content)

        attack_patterns = self.create_attack_patterns(entity_id, ttps)

        # Attack patterns can be assigned as objects in the report.
        # However, in stix2, they are supposed to be linked to malwares or intrusion sets
        # (`attack-pattern` uses `malware` and `intrusion sets` uses `attack-pattern`)
        # If the report contains malwares or intrusion sets and the flag is set, they will be linked
        # to the new attack patterns.
        malwares = [i for i in report["objects"] if i["entity_type"] == "Malware"]
        intrusion_sets = [
            i for i in report["objects"] if i["entity_type"] == "Intrusion-Set"
        ]

        if self.link_to_malware and malwares:
            self.helper.log_info(
                f"Attack pattern will be linked to the malwares {malwares}"
            )
            self.link_attack_patterns_to_malwares(entity_id, attack_patterns, malwares)

        if self.link_to_intrusion_set and intrusion_sets:
            self.helper.log_info(
                f"Intrusions sets {intrusion_sets} will be linked to the attack patterns"
            )
            self.link_intrusion_sets_to_attack_patterns(
                entity_id, intrusion_sets, attack_patterns
            )

        self.helper.log_info(
            f"Added {len(attack_patterns)} attack patterns to the report"
        )
        return f"Added {len(attack_patterns)} attack patterns to the report"

    def create_attack_patterns(
        self, report_id: str, ttps: List[Tuple[str, str]]
    ) -> List:
        """
        Create the given attack patterns and add them to the report.

        Parameters
        ----------
        report_id : str
            Id of the initial report.
        ttps : list of string tuple
            List containing the name and the mitre id of the attack patterns

        Returns
        -------
        list
            List of newly created attack patterns.
        """
        attacks = []
        for ttp in ttps:
            attack_pattern = self.helper.api.attack_pattern.create(
                stix_id=AttackPattern.generate_id(name=ttp[0], x_mitre_id=ttp[1]),
                name=ttp[0],
                x_mitre_id=ttp[1],
                createdBy=self.author["standard_id"],
            )
            attacks.append(attack_pattern)
            self.helper.api.report.add_stix_object_or_stix_relationship(
                id=report_id, stixObjectOrStixRelationshipId=attack_pattern["id"]
            )
            self.helper.metrics.inc("record_send", n=2)
            self.helper.log_debug(f"Attack pattern created: {attack_pattern}")

        return attacks

    def link_attack_patterns_to_malwares(self, report_id, attack_patterns, malwares):
        """
        Link the malwares of the report to the predicted attack patterns.

        Parameters
        ----------
        report_id : str
            Id of the initial report.
        attack_patterns : list
            List of predicted attack patterns
        malwares : list
            List of malwares linked to the report.
        """
        for attack_pattern in attack_patterns:
            for malware in malwares:
                self.helper.log_info(
                    f"Adding attack pattern {attack_pattern} to malware {malware}"
                )
                rel = self.helper.api.stix_core_relationship.create(
                    fromId=attack_pattern["standard_id"],
                    toId=malware["standard_id"],
                    relationship_type="uses",
                    confidence=self.helper.connect_confidence_level,
                    createdBy=self.author["standard_id"],
                )
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=report_id,
                    stixObjectOrStixRelationshipId=rel["id"],
                )
                self.helper.metrics.inc("record_send", n=2)
                self.helper.log_debug(f"Relationship to add: {rel}")

    def link_intrusion_sets_to_attack_patterns(
        self, report_id: str, intrusion_sets: List, attack_patterns: List
    ):
        """
        Link the intrusion sets of the report to the predicted attack patterns.

        Parameters
        ----------
        report_id : str
            Id of the initial report.
        intrusion_sets : list
            List of intrusion sets linked to the report.
        attack_patterns : list
            List of predicted attack patterns
        """
        for attack_pattern in attack_patterns:
            for intrusion in intrusion_sets:
                self.helper.log_info(
                    f"Adding intrusion set {intrusion} to attack pattern {attack_pattern}"
                )
                rel = self.helper.api.stix_core_relationship.create(
                    fromId=intrusion["standard_id"],
                    toId=attack_pattern["standard_id"],
                    relationship_type="uses",
                    confidence=self.helper.connect_confidence_level,
                    createdBy=self.author["standard_id"],
                )
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=report_id,
                    stixObjectOrStixRelationshipId=rel["id"],
                )
                self.helper.metrics.inc("record_send", n=2)
                self.helper.log_debug(f"Relationship to add: {rel}")

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
