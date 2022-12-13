# -*- coding: utf-8 -*-
"""VMRay enrichment module builder."""

import json
import datetime

from typing import Any, Union, List, Dict, Tuple, Set

import validators
import plyara

from pycti import OpenCTIConnectorHelper, StixCyberObservable

from stix2 import (
    Bundle,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    Identity,
    Indicator,
    IPv4Address,
    Relationship,
    Report,
    TLP_AMBER,
    URL,
)

from .models.text import Text
from .models.relationship_ref import RelationshipRef
from .utils.utils import deep_get, format_domain, format_email_address
from .utils.constants import (
    BLACKLIST_DOMAIN,
    INVALID_DOMAIN,
    STATIC_DATA_FIELD,
    SAMPLE_TYPE,
    EntityType,
    InfoMessage,
    RelationshipType,
    ErrorMessage,
)


class VMRAYBuilder:
    """
    VMRay builder.
    Provide functions to build STIX entities
    """

    _SPEC_VERSION = "2.1"

    def __init__(
        self,
        author: Identity,
        run_on_s: bool,
        analysis: dict,
        helper: OpenCTIConnectorHelper,
    ):
        """Initialize VMRayBuilder."""
        self.author = author
        self.run_on_s = run_on_s
        self.object_refs: List[str] = []
        self.relationships: Set[RelationshipRef] = set()
        self.sample: Union[None, Tuple[str, File]] = None
        self.bundle = []
        self.helper = helper

        # Make sure the analysis is correctly structured
        if (
            isinstance(analysis, dict)
            and isinstance(analysis["sample_details"], dict)
            and isinstance(analysis["summary"], str)
        ):
            if not analysis.get("summary") or not analysis.get("sample_details"):
                raise KeyError(ErrorMessage.WRONG_ANALYSIS.format("BUILDER"))
        else:
            raise TypeError(ErrorMessage.POORLY_TYPED_ANALYSED.format("BUILDER"))

        # Initialize local analysis
        self.summary = json.loads(analysis["summary"])
        self.sample_details = analysis["sample_details"]

        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": author["id"],
        }

        # Retrieve the sample
        self.sample = self.get_sample()

        if self.sample is None:
            self.helper.log_warning(
                "The root sample was not found in the summary, "
                "this information in mandatory in order to build relationships."
            )

    def create_file(self, file: Dict[str, Any]) -> str:
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
        # Default values
        filename = None

        # Check for non-empty hash and hash with a length greater than 4 characters
        hashes = {
            k: v
            for k, v in file.get("hash_values").items()
            if (v is not None and len(v) > 4)
        }

        # Try to set a filename
        if file.get("ref_filenames"):
            for ref in file.get("ref_filenames"):
                # Set the filename if possible
                filename = deep_get(
                    self.summary,
                    *ref["path"][:2],
                    "filename",
                    default=hashes.get("sha256"),
                )
        else:
            # No filename found, use the hash
            filename = hashes.get("sha256")

        sco_obj = File(
            hashes=hashes,
            type=EntityType.FILE.value,
            spec_version=self._SPEC_VERSION,
            name=filename,
            object_marking_refs=TLP_AMBER,
            mime_type=file.get("mime_type"),
            size=file.get("size"),
            custom_properties=self.custom_props,
        )

        if self.sample and sco_obj.id != self.sample[1].id:
            self.relationships.add(RelationshipRef(self.sample[1].id, sco_obj.id))
        if self.get_from_bundle(EntityType.FILE.value, sco_obj.id, "id") is None:
            self.bundle.append(sco_obj)
            self.object_refs.append(sco_obj.id)

        return sco_obj.id

    def create_ip(self, ip_addr: Dict[str, Any]) -> None:
        """
        Create a STIX ip_address SCO and append it to the bundle.

        Parameters
        ----------
        ip_addr: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: ip_address_0)
        Raise
        -------
        ValueError
            * If the ip address value is invalid
        """
        if not validators.ipv4(ip_addr["ip_address"]):
            raise ValueError(
                ErrorMessage.INVALID_VALUE.format("IP", ip_addr["ip_address"])
            )

        sco_obj = IPv4Address(
            type=EntityType.IPV4_ADDR.value,
            spec_version=self._SPEC_VERSION,
            value=ip_addr.get("ip_address"),
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        # Check for relation to domain (resolves-to)
        if ip_addr.get("ref_domains"):
            for ref in ip_addr.get("ref_domains"):
                obj = ref["path"]
                raw_domain = deep_get(self.summary, *obj[:2])
                if raw_domain:
                    # Domain found in the summary, check in the bundle
                    domain = self.get_from_bundle(
                        EntityType.DOMAIN_NAME.value, raw_domain["domain"], "value"
                    )
                    if domain:
                        # Domain in the bundle, create a relationship
                        self.relationships.add(
                            RelationshipRef(
                                domain.id, sco_obj.id, RelationshipType.RESOLVES.value
                            )
                        )

        if self.sample:
            self.relationships.add(RelationshipRef(self.sample[1].id, sco_obj.id))

        self.object_refs.append(sco_obj.id)
        self.bundle.append(sco_obj)

    def create_url(self, url: Dict[str, Any]) -> str:
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
        Returns
        -------
        str:
            The id of the generated stix URL
        """
        if not validators.url(url["url"]):
            raise ValueError(ErrorMessage.INVALID_VALUE.format("URL", url["url"]))

        sco_obj = URL(
            value=url["url"],
            type=EntityType.URL.value,
            spec_version=self._SPEC_VERSION,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        if self.sample and sco_obj.id != self.sample[1].id:
            self.relationships.add(RelationshipRef(self.sample[1].id, sco_obj.id))

        if self.get_from_bundle(EntityType.URL.value, sco_obj.id, "id") is None:
            self.bundle.append(sco_obj)
            self.object_refs.append(sco_obj.id)

        return sco_obj.id

    def create_email_address(self, email: Dict[str, Any]) -> str:
        """
        Create a STIX email_address SCO and append it to the bundle.

        Parameters
        ----------
        email: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: email_address_0)
         Raise
        -------
        ValueError
            * If the email address value is invalid
        Returns
        -------
        str:
            The id of the generated stix email address
        """
        # Default values
        email_address = email.get("email_address")
        email_formatted = format_email_address(email_address)

        # If the email-address is not valid, raise a ValueError
        if email_formatted is None or not validators.email(email_formatted):
            raise ValueError(
                ErrorMessage.INVALID_VALUE.format("EMAIL_ADDRESS", email_address)
            )

        self.helper.log_debug(
            InfoMessage.CREATE_EMAIL_ADDR.format(
                "CREATE_EMAIL_ADDRESS", email_formatted
            )
        )

        sco_obj = EmailAddress(
            value=email_formatted,
            type=EntityType.EMAIL_ADDR.value,
            spec_version=self._SPEC_VERSION,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        if self.get_from_bundle(EntityType.EMAIL_ADDR.value, sco_obj.id, "id") is None:
            self.bundle.append(sco_obj)
            self.object_refs.append(sco_obj.id)
        if self.sample:
            self.relationships.add(RelationshipRef(self.sample[1].id, sco_obj.id))

        return sco_obj.id

    def create_email_message(self, email: Dict[str, Any]) -> str:
        """
        Create a STIX email_message SCO and append it to the bundle.

        Parameters
        ----------
        email: dict[str, Any]
            * The analysis's chunk needed to generate the object (ex: email_0)
        Returns
        -------
        str:
            The id of the generated stix email message
        """
        # Default values
        from_ref = None
        to_refs = []

        # Check if each address exist in the email_addresses key of the summary
        for raw_email in self.summary.get("email_addresses").values():
            if raw_email.get("email_address") == email.get("sender"):
                self.helper.log_debug(
                    f"SENDER : Email {email.get('sender')} found in the summary"
                )
                from_ref = self.get_from_bundle(
                    EntityType.EMAIL_ADDR.value,
                    self.create_email_address(raw_email),
                    "id",
                )
            if raw_email.get("email_address") in email.get("recipients"):
                self.helper.log_debug(
                    f"RECIPIENTS : Email {email.get('email_address')} found in the summary"
                )
                to_refs.append(
                    self.get_from_bundle(
                        EntityType.EMAIL_ADDR.value,
                        self.create_email_address(raw_email),
                        "id",
                    )
                )

        sco_obj = EmailMessage(
            type=EntityType.EMAIL_MESSAGE.value,
            is_multipart=True,
            spec_version=self._SPEC_VERSION,
            from_ref=from_ref,
            to_refs=to_refs,
            subject=email.get("subject"),
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        # Check if each attachment exist in the files key of the summary
        if email.get("ref_attachments"):
            for ref in email.get("ref_attachments"):
                # File in the bundle, create the file and the relationship
                raw_file = deep_get(self.summary, ref["path"][0], ref["path"][1])
                if raw_file:
                    self.relationships.add(
                        RelationshipRef(
                            sco_obj.id,
                            self.create_file(raw_file),
                            description="Email attachment",
                        )
                    )

        if self.sample and sco_obj.id != self.sample[1].id:
            self.relationships.add(RelationshipRef(self.sample[1].id, sco_obj.id))

        if (
            self.get_from_bundle(EntityType.EMAIL_MESSAGE.value, sco_obj.id, "id")
            is None
        ):
            self.object_refs.append(sco_obj.id)
            self.bundle.append(sco_obj)

        return sco_obj.id

    def create_domain(self, domain: Dict[str, Any]) -> None:
        """
        Create a STIX domain SCO and append it to the bundle.
        The sco is not created if the domain-name concerned is blacklisted.

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
        domain_formatted = format_domain(domain_name)

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
                InfoMessage.BLACKLISTED_VALUE.format("DOMAIN-NAME", domain_name)
            )
            return

        sco_obj = DomainName(
            type=EntityType.DOMAIN_NAME.value,
            spec_version=self._SPEC_VERSION,
            value=domain_name,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        if self.sample:
            self.relationships.add(RelationshipRef(self.sample[1].id, sco_obj.id))

        self.object_refs.append(sco_obj.id)
        self.bundle.append(sco_obj)

    def create_text(self, static_data: Dict[str, Any]) -> None:
        """
        Create a STIX Text custom object and append it to the bundle.

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
            custom_obj = Text(
                value=values,
                object_marking_refs=TLP_AMBER,
                spec_version=self._SPEC_VERSION,
                custom_properties=self.custom_props,
            )
            if self.sample:
                self.relationships.add(
                    RelationshipRef(self.sample[1].id, custom_obj.id)
                )

            self.object_refs.append(custom_obj.id)
            self.bundle.append(custom_obj)
        else:
            self.helper.log_debug(
                "Text not created, not data to process in this static_data key"
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
            name=yara_rule.get("rule_name", "No rulename provided"),
            description=description,
            type=EntityType.INDICATOR.value,
            spec_version=self._SPEC_VERSION,
            confidence=self.helper.connect_confidence_level,
            pattern_type="yara",
            pattern=plyara.utils.rebuild_yara_rule(yara_rule),
            valid_from=self.get_analysis_date(),
            created_by_ref=self.author,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        if self.sample:
            self.relationships.add(RelationshipRef(self.sample[1].id, sdo_obj.id))

        self.object_refs.append(sdo_obj.id)
        self.bundle.append(sdo_obj)

    def create_relationship(self, rel: RelationshipRef) -> None:
        """
        Create a STIX Relationship and append it to the bundle.
        To avoid circular dependency, target_id and sample_id must be different.

        Parameters
        ----------
        rel: RelationshipRef
            * The instance that contains the source,
            the target and the description to build the relationship.
        """
        if rel.source != rel.target:
            obj_rel = Relationship(
                created_by_ref=self.author,
                type=EntityType.RELATIONSHIP.value,
                spec_version=self._SPEC_VERSION,
                relationship_type=rel.relationship_type,
                description=rel.description,
                source_ref=rel.source,
                target_ref=rel.target,
                confidence=self.helper.connect_confidence_level,
                custom_properties=self.custom_props,
            )
            self.bundle.append(obj_rel)

    def create_report(self, stix_id=None) -> None:
        """
        Create a STIX Report and append it to the bundle.

        Parameters
        ----------
        stix_id: str
            * The stix file sent by OpenCti
        Raise
        -------
        KeyError
            * If the key "analysis_metadata" is not found in the summary
        """
        # Check if the target key exist in the analysis
        if self.summary.get("analysis_metadata") is None:
            raise KeyError(ErrorMessage.ANALYSIS_METADATA_NOT_FOUND.format("REPORT"))

        # Default data
        metadata = self.summary["analysis_metadata"]
        description = set()
        labels = set()

        # Generate Labels and description
        if self.summary.get("classifications") is not None:
            self.helper.log_debug(
                f"[REPORT] - Label {self.summary.get('classifications')} found in classifications"
            )
            labels.update(self.summary["classifications"])

        if "matches" in self.summary.get("vti"):
            # target = self.summary.get("vti").get("matches")
            target = deep_get(self.summary, "vti", "matches")
            # Append label(s) found in vtis
            for vti in target:
                # Retrieve VTI data
                category_desc = deep_get(target, vti, "category_desc")
                operation_desc = deep_get(target, vti, "operation_desc")
                # Add label field
                if category_desc is not None:
                    self.helper.log_debug(
                        f"[REPORT] - Label {category_desc} found in vti {vti}"
                    )
                    labels.add(category_desc)
                # Add description field
                if operation_desc is not None:
                    self.helper.log_debug(
                        f"[REPORT] - Description {operation_desc} found in vti {vti}"
                    )
                    description.add(operation_desc)

        # Control description field
        description = ",".join(description) if description else None

        # Set name
        name = f"VMRay analysis ID {metadata.get('analysis_id', 'unknown')}"

        # Add the sample analyzed into the object_refs list
        if stix_id:
            self.object_refs.append(stix_id)

        # Generate the STIX object
        obj_report = Report(
            name=name,
            description=description,
            object_refs=self.object_refs,
            type=EntityType.REPORT.value,
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
        self.helper.log_debug(
            f"Generating a bundle with {len(self.bundle) + 2} stix objects"
        )
        return Bundle(
            type=EntityType.BUNDLE.value,
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
        # Get current date if field 'DateTime' doesn't exist
        metadata = self.summary.get("analysis_metadata")
        analysis_date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        if metadata:
            if "offsetDateTime" in metadata.get("creation_time", {}):
                # Set analysis_date variable
                analysis_date = deep_get(metadata, "creation_time", "offsetDateTime")
                self.helper.log_info(
                    InfoMessage.ANALYSIS_DATE_FOUND.format(
                        "GET_ANALYSIS_DATE", analysis_date
                    )
                )
            else:
                self.helper.log_info(
                    InfoMessage.ANALYSIS_DATE_NOT_FOUND.format("GET_ANALYSIS_DATE")
                )

        return analysis_date

    def get_from_bundle(
        self, stix_type: str, value: str, *keys: str
    ) -> Union[StixCyberObservable, None]:
        """
        Retrieve a specific object from the bundle.

        Parameters
        ----------
        stix_type: str
            * The type of STIX object, field type in the entity will be compare
        value: str
            * The value associated to the corresponding key
        keys: str
            * The key to lookup in the STIX object, can be nested
        Returns
        -------
        StixCyberObservable:
            * The entity found in the bundle
        """
        for entity in self.bundle:
            if entity["type"] == stix_type:
                if deep_get(entity, *keys) == value:
                    return entity
        # Return None if the stix is not found
        return None

    def get_sample(self) -> Union[Tuple[str, Union[File, URL, EmailMessage]], None]:
        """
        Create the root sample depending on the field "is_sample: bool".
        The type of sample that will be processed is either a file, an email or a url.
        Returns
        -------
        tuple(str, StixCyberObservable):
            str : The key in the summary used to generate the entity
            StixCyberObservable : The entity created
        """
        # Retrieve type in the analysis_metadata
        smpl = deep_get(self.summary, "analysis_metadata", "sample_type")
        if smpl:
            self.helper.log_info(
                InfoMessage.SAMPLE_TYPE_FOUND.format("GET_SAMPLE", smpl)
            )
            # Sample type could be of type url, email or file, default case is FILE
            smpl = smpl if smpl in SAMPLE_TYPE else "FILE"
            for key, value in SAMPLE_TYPE[smpl].items():
                (sum_key, sum_data) = next(
                    (
                        sco
                        for sco in self.summary[value.get("key")].items()
                        if sco[1].get("is_sample")
                    ),
                    (None, ""),
                )
                if sum_key:
                    return (
                        sum_key,
                        self.get_from_bundle(
                            key, getattr(self, value.get("transform"))(sum_data), "id"
                        ),
                    )
        self.helper.log_info(
            InfoMessage.SAMPLE_TYPE_NOT_FOUND.format(
                "GET_SAMPLE", deep_get(self.summary, "analysis_metadata", "analysis_id")
            )
        )
        # Return None if no sample where found
        return None
