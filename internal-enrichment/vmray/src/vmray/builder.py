# pylint: disable=too-few-public-methods
# -*- coding: utf-8 -*-
"""VMRay enrichment module."""

from dataclasses import dataclass
import json
import datetime
from urllib.parse import urlparse
from typing import Any, Union, List
import plyara
import validators

from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils, StixCyberObservable 
from stix2 import (
    Bundle,
    Report,
    DomainName,
    EmailAddress,
    File,
    Identity,
    Indicator,
    IPv4Address,
    URL,
    Relationship,
    TLP_AMBER,
    CustomObservable,
    properties,
)
from .constants import BLACKLIST_DOMAIN, INVALID_DOMAIN, STATIC_DATA_FIELD, ErrorMessage


@CustomObservable(
    "x-opencti-text",
    [
        ("value", properties.StringProperty(required=True)),
        ("object_marking_refs", TLP_AMBER),
    ],
)
class OpenCtiText:
    """Wrapper class for CustomObservable"""


@dataclass
class RelationshipRef:
    """
    This class represent the needed values to build a STIX relationship.
    Parameters
    ----------
    description: str
        * The description field used to build the SRO
    target: str
        * The target id used to build the SRO
    source: str
        * The source id used to build the SRO
    """

    source: str
    target: str
    description: str = "VMRay: sample to IOC"


class VMRAYBuilder:
    """
    VMRay builder.
    Provide functions to build STIX entities
    """

    _SPEC_VERSION = "2.1"

    def __init__(self, author: Identity, run_on_s: bool, analysis: dict, helper: OpenCTIConnectorHelper):
        """Initialize VMRayBuilder."""
        self.author = author
        self.run_on_s = run_on_s
        self.object_refs: List[RelationshipRef] = []
        self.bundle = []
        self.helper = helper
        self.sample_id = None

        # Make sure the analysis is correctly structured
        if (
            isinstance(analysis, dict)
            and isinstance(analysis["sample_details"], dict)
            and isinstance(analysis["summary"], str)
        ):
            if not analysis.get("summary") or not analysis.get("sample_details"):
                raise KeyError("The analysis sent to the builder is inconsistent")
        else:
            raise TypeError(
                "The analysis sent to the builder does not respect the mandatory types,"
                + "field 'sample_details' must be of type dict and field 'summary' must be of type str"
            )

        # Initialize local analysis
        self.summary = json.loads(analysis["summary"])
        self.sample_details = analysis["sample_details"]

        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": author["id"],
            "x_metis_modified_on_s": run_on_s,
        }
        # Retrieve the sample id
        self.sample_id = self.get_sample_id()
        if self.sample_id is None:
            self.helper.log_error(
                "The root sample was not found in the summary, this information in mandatory in order to build relationships."
            )
            raise ValueError("Root sample not found, operation aborted")

    def create_file(self, file: dict[str, Any]) -> str:
        """
        Create a STIX file SCO and append it to the bundle.

        Parameters
        ----------
        file: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: file_0)
        Returns
        -------
        str:
            The id of the generated stix file
        """
        # Check for non-empty hash and hash with a length greater than 4 characters
        hashes = {
            k: v
            for k, v in file.get("hash_values").items()
            if (v is not None and len(v) > 4)
        }
        # stix_id = self.get_id("file")
        filename = None

        # Try to set a filename
        if file.get("ref_filenames"):
            for ref in file.get("ref_filenames"):
                # Set the filename
                filename = (
                    self.summary.get(ref["path"][0]).get(ref["path"][1]).get("filename")
                )
        else:
            # No filename found, use the hash
            filename = hashes.get("sha256")

        sco_obj = File(
            id=self.get_id("file"),
            hashes=hashes,
            type="file",
            spec_version=self._SPEC_VERSION,
            name=filename,
            object_marking_refs=TLP_AMBER,
            mime_type=file.get("mime_type"),
            size=file.get("size"),
            custom_properties=self.custom_props,
        )

        if not file.get("is_sample"):
            # If the file is not the sample, we need a relation
            self.object_refs.append(RelationshipRef(self.sample_id, sco_obj.id))

        self.bundle.append(sco_obj)
        return sco_obj.id

    def create_ip(self, ip: dict[str, Any]) -> None:
        """
        Create a STIX ip_address SCO and append it to the bundle.
        Parameters
        ----------
        ip: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: ip_address_0)
        Raise
        -------
        ValueError
            * If the ip address value is invalid
        """
        if not validators.ipv4(ip["ip_address"]):
            raise ValueError(ErrorMessage.INVALID_VALUE.format("IP", ip["ip_address"]))

        sco_obj = IPv4Address(
            id=self.get_id("ipv4-addr"),
            type="ipv4-addr",
            spec_version=self._SPEC_VERSION,
            value=ip.get("ip_address"),
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(sco_obj)
        self.object_refs.append(RelationshipRef(self.sample_id, sco_obj.id))

    def create_url(self, url: dict[str, Any]) -> None:
        """
        Create a STIX url SCO and append it to the bundle.
        Parameters
        ----------
        url: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: url_0)
        Raise
        -------
        ValueError
            * If the url value is invalid
        """
        if not validators.url(url["url"]):
            raise ValueError(ErrorMessage.INVALID_VALUE.format("URL", url["url"]))

        sco_obj = URL(
            id=self.get_id("url"),
            value=url["url"],
            type="url",
            spec_version=self._SPEC_VERSION,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(sco_obj)
        self.object_refs.append(RelationshipRef(self.sample_id, sco_obj.id))

    def create_email_address(self, email: dict[str, Any]) -> None:
        """
        Create a STIX email_address SCO and append it to the bundle.
        Parameters
        ----------
        email: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: email_address_0)
        """
        sco_obj = EmailAddress(
            id=self.get_id("email-addr"),
            value=email["email_address"],
            type="email-addr",
            spec_version=self._SPEC_VERSION,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(sco_obj)
        self.object_refs.append(RelationshipRef(self.sample_id, sco_obj.id))

    def create_domain(self, domain: dict[str, Any]) -> None:
        """
        Create a STIX domain SCO and append it to the bundle.
        The sco is not created if the domain-name process is blacklisted.
        Parameters
        ----------
        domain: dict[str, Any]
            *The analysis's chunk needed to generate the object (ex: domain_0)
        Raise
        -------
        ValueError
            * If the domain name value is invalid
        """
        # Default values
        domain_name = domain.get("domain")
        domain_formatted = self.format_domain(domain_name)

        # If the domain name is empty or not valid, raise a ValueError
        if (
            not domain_name
            or not validators.domain(domain_formatted)
            or domain_name in INVALID_DOMAIN
        ):
            raise ValueError(
                ErrorMessage.INVALID_VALUE.format("DOMAIN-NAME", domain_name)
            )

        # If the domain name is blacklisted, return None
        if domain_formatted in BLACKLIST_DOMAIN:
            self.helper.log_info(
                ErrorMessage.BLACKLISTED_VALUE.format("DOMAIN-NAME", domain_name)
            )
            return

        sco_obj = DomainName(
            id=self.get_id("domain-name"),
            type="domain-name",
            spec_version=self._SPEC_VERSION,
            value=domain_name,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(sco_obj)
        self.object_refs.append(RelationshipRef(self.sample_id, sco_obj.id))

    def create_xopenctitext(self, static_data: dict[str, Any]) -> None:
        """
        Create a STIX OpenCtiText custom object and append it to the bundle.
        Parameters
        ----------
        static_data: dict[str, Any]
            * The static data needed to generate the object
        """
        temp_dict = {}
        values = ""

        for key in STATIC_DATA_FIELD:
            if static_data.get(key):
                temp_dict.update({key: static_data[key]})
        if temp_dict:
            values = str(json.dumps(temp_dict))

        if values:
            custom_obj = OpenCtiText(
                value=values,
                spec_version=self._SPEC_VERSION,
                object_marking_refs=TLP_AMBER,
                custom_properties=self.custom_props,
            )
            self.bundle.append(custom_obj)
            self.object_refs.append(RelationshipRef(self.sample_id, custom_obj.id))
        else:
            self.helper.log_debug(
                "OpenCtiText not created, not data to process in this static_data key"
            )

    def create_yara_indicator(
        self, ruleset_id, ruleset_name, description, yara_rule
    ) -> None:
        """
        Format a Yara rule to a STIX indicator
        Parameters
        ----------
        ruleset_id: str
            * ruleset_id retrieve from the summary's yara key
        ruleset_name: str
            * ruleset_name retrieve from the summary's yara key
        description: str
            * description retrieve from the summary's yara key
        yara_rule : dict
            * The yara rule (as parsed by plyara).
        """
        # If description is empty, don't add it to the final description
        if description:
            description = (
                f"{description}. (Ruleset | name: {ruleset_name}, id: {ruleset_id})"
            )
        else:
            description = f"(Ruleset | name: {ruleset_name}, id: {ruleset_id})"

        sdo_obj = Indicator(
            id=self.get_id("indicator"),
            name=yara_rule.get("rule_name", "No rulename provided"),
            description=description,
            type="indicator",
            spec_version=self._SPEC_VERSION,
            confidence=self.helper.connect_confidence_level,
            pattern_type="yara",
            pattern=plyara.utils.rebuild_yara_rule(yara_rule),
            valid_from=self.get_analysis_date(),
            created_by_ref=self.author,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(sdo_obj)
        self.object_refs.append(RelationshipRef(self.sample_id, sdo_obj.id))

    def create_relationship(self, rel: RelationshipRef) -> None:
        """
        Create a STIX Relationship and append it to the bundle.
        To avoid circular dependency, target_id and sample_id must be different
        Parameters
        ----------
        rel: RelationshipRef
            * The instance that contains the source, the target and the description to build the relationship.
        """
        if rel.source != rel.target:
            obj_rel = Relationship(
                id=self.get_id("relationship"),
                created_by_ref=self.author,
                type="relationship",
                spec_version=self._SPEC_VERSION,
                relationship_type="related-to",
                description=rel.description,
                source_ref=rel.source,
                target_ref=rel.target,
                confidence=self.helper.connect_confidence_level,
                custom_properties=self.custom_props,
            )
            self.bundle.append(obj_rel)

    def create_report(self) -> None:
        """
        Create a STIX Report and append it to the bundle.ß
        Raise
        -------
        KeyError
            * If the key "analysis_metadata" is not found in the summary
        """
        # Check if the target key exist in the analysis
        if self.summary.get("analysis_metadata") is None:
            raise KeyError(
                "'analysis_metadata' not found in the analysis, report generation aborted"
            )

        # Default data
        metadata = self.summary["analysis_metadata"]
        description = set()
        labels = set()

        # Generate Labels and description
        if self.summary.get("classifications") is not None:
            self.helper.log_info("Field classification found, adding label")
            labels.update(self.summary["classifications"])

        if "matches" in self.summary.get("vti"):
            target = self.summary.get("vti").get("matches")
            # Append label(s) found in vtis
            for vti in target:
                self.helper.log_info(f"VTI found in the summary ({vti})")
                if "category_desc" in target.get(vti):
                    self.helper.log_info(
                        f"Label {target.get(vti).get('category_desc')} found in vti {vti}"
                    )
                    labels.add(target.get(vti).get("category_desc"))
                # Add description field
                if "operation_desc" in target.get(vti):
                    if target.get(vti).get("operation_desc"):
                        description.add(target.get(vti).get("operation_desc"))

        # Control description field
        description = ",".join(description) if description else None

        # Set name
        name = f"VMRay analysis ID {metadata.get('analysis_id', 'unknown')}"

        # Build object_refs with the sample
        object_refs = [ref.target for ref in self.object_refs] + [self.sample_id]

        # Generate the STIX object
        obj_report = Report(
            name=name,
            description=description,
            object_refs=object_refs,
            type="report",
            spec_version=self._SPEC_VERSION,
            labels=list(labels),
            published=self.get_analysis_date(),
            report_types=["malware"],
            confidence=self.helper.connect_confidence_level,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(obj_report)

    def create_bundle(self) -> Bundle:
        """
        Create a bundle containing the author and the enrichment entities.
        Note: `allow_custom` must be set to True in order to specify the author of an object.
        Returns
        -------
        Bundle :
            * The STIX Bundle generated
        """
        self.helper.log_info(f"Generate bundle with {len(self.bundle)} stix objects")
        return Bundle(
            type="bundle",
            objects=[self.author, TLP_AMBER] + self.bundle,
            allow_custom=True,
        )

    # ===== UTILS ===== #

    def get_analysis_date(self) -> str:
        """
        This method return the date of the analysis retrieve from the summary.
        If the date field is not found, the current date is retrieve.
        Returns
        -------
        str:
            * The date of the analysis with the format "%Y-%m-%dT%H:%M:%SZ"
        """
        # Get current date if field 'offsetDateTime' doesn't exist
        metadata = self.summary.get("analysis_metadata")
        analysis_date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        if metadata:
            if "offsetDateTime" in metadata.get("creation_time", {}):
                self.helper.log_info("Field offsetDateTime found, setting value")
                # Set analysis_date variable
                analysis_date = metadata.get("creation_time").get("offsetDateTime")
            else:
                self.helper.log_info(
                    "Field offsetDateTime not found, using current date"
                )

        return analysis_date

    def find_from_bundle(
        self, stix_type: str, key: str, value: str
    ) -> Union[StixCyberObservable, None]:
        """
        Retrieve a specific object from the bundle.
        Parameters
        ----------
        stix_type: str
            * The type of STIX object, field type in the entity will be compare
        key: str
            * The key to lookup in the STIX object
        value: str
            * The value associated to the corresponding key
        """
        for entity in self.bundle:
            if entity["type"] == stix_type and entity.get(key):
                if entity[key] == value:
                    return entity
        # Return None if the sample is not found
        return None

    def get_sample_id(self) -> Union[str, None]:
        """
        Find the root sample in the summary. The root sample is the file_0 in the summary.
        Returns
        -------
        str:
            The id of the root sample
        """
        for f in self.summary.get("files"):
            file = self.summary["files"][f]
            if file.get("is_sample"):
                sample = self.create_file(file)
                self.helper.log_info(f"Sample ID found : {sample}")
                return sample
        return None

    @staticmethod
    def get_id(stix_type: str) -> str:
        """
        Create a STIX id using the OpenCTIStix2 library
        Parameters
        ----------
        stix_type: str
            * The type of stix id to generate
        Returns
        -------
        str:
            * A valid STIX id
        """
        return OpenCTIStix2Utils.generate_random_stix_id(stix_type)

    @staticmethod
    def format_domain(url: str) -> str:
        """
        This method remove 'http://', 'https://' and 'www.' in the url parameter.
        Some examples :
            * http://test.com --> test.com
            * https://test.com --> test.com
            * http://www.test.com --> test.com
            * www.test.com --> test.com
        Parameters
        ----------
        url: str
            * The string that will be process
        Returns
        -------
        str:
            * A formatted string that contains the desired domain-name format
        """
        # Format url
        formatted = urlparse(url)
        result = ""
        # Check if netloc/path is not empty
        if formatted.netloc:
            result = formatted.netloc
        elif formatted.path:
            result = formatted.path
        # Replace www. if it exists in the string
        return result.replace("www.", "")
