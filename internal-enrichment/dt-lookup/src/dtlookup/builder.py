# -*- coding: utf-8 -*-
"""Builder for DT-Lookup."""

import ipaddress
import json
from typing import Any, Optional, Union

from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils
from stix2 import (
    AutonomousSystem,
    Bundle,
    DomainName,
    EmailAddress,
    Identity,
    IPv4Address,
    Relationship,
    TLP_AMBER,
)

from .constants import EntityType, CONTACTS_TYPE


class DtBuilder:
    """
    DomainTools builder.
    Create the STIX objects and relationships.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        score: Optional[int],
        run_on_s: bool,
    ):
        """Initialize DtBuilder."""
        self.helper = helper
        self.author = author
        self.run_on_s = run_on_s

        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": author["id"],
            "x_metis_modified_on_s": run_on_s,
        }
        if score is not None:
            self.custom_props["x_opencti_score"] = score

        self.bundle: list[
            Union[AutonomousSystem, DomainName, EmailAddress, IPv4Address, Relationship]
        ] = []

    @staticmethod
    def decimal_to_ip(ip: int) -> str:
        """
        Convert a decimal value to an IP.

        Returns
        -------
        str
            The converted IP, as string.
        """
        return str(ipaddress.ip_address(ip))

    def create_domain(self, domain: str) -> str:
        """
        Create a domain object with the author and custom properties.

        Parameters
        ----------
        domain : str
            Domain to create.

        Returns
        -------
        str
            Id of the inserted domain.
        """
        domain_obj = DomainName(
            id=OpenCTIStix2Utils.generate_random_stix_id("domain-name"),
            type="domain-name",
            value=domain,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )
        self.bundle.append(domain_obj)
        return domain_obj.id

    def create_identity(self, contact: dict[str, Any]) -> str:
        """
        Create an `identity` based on the contact information.

        Parameters
        ----------
        contact : dict
            Dictionary with the contact information.

        Returns
        -------
        str
            Id of the inserted identity.
        """
        infos = {
            "Street": contact.get("str", None),
            "City": contact.get("city", None),
            "Region": contact.get("reg", None),
            "Postal code": contact.get("pc", None),
            "Country code": contact.get("cc", None),
            "Phone": contact.get("ph", None),
            "Fax": contact.get("fx", None),
        }
        identity = Identity(
            id=OpenCTIStix2Utils.generate_random_stix_id("identity"),
            name=contact.get("org") or contact.get("nm"),
            roles=[CONTACTS_TYPE[t] for t in contact["t"]],
            identity_class="organization",
            contact_information=json.dumps(infos),
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(identity)
        return identity.id

    def create_resolves_to(
        self, source_id: str, target_id: str, description: Optional[str] = None
    ):
        """
        Create the `resolves-to` relationship between the source and the target.

        The source_id needs to belong to a `domain-name` object and the target_id to
        either a domain of `ipv4-addr` object.

        Parameters
        ----------
        source_id : str
            Id of the source.
        target_id : str
            Id of the target.
        description : str
            Description of the relationship (e.g. the type (name-server, redirect, etc).
        """
        domain_to_target = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="resolves-to",
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            description=description,
            custom_properties={"x_metis_modified_on_s": self.run_on_s},
        )

        self.bundle.append(domain_to_target)

    def create_related_to(
        self, source_id: str, target_id: str, description: Optional[str] = None
    ):
        """
        Create the `related-to` relationship between the source and the target.

        Parameters
        ----------
        source_id : str
            Id of the source.
        target_id : str
            Id of the target.
        description : str
            Description of the relationship.
        """
        rel = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="related-to",
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            description=description,
            custom_properties={"x_metis_modified_on_s": self.run_on_s},
        )

        self.bundle.append(rel)

    def link_domain_related_to_email(self, source: str, target: str, description: str):
        """
        Create the `related-to` relationship between the `domain-name` and the `email-addr`.
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source : str
            Value of the source (domain-name) of the relationship.
        target : str
            Value of the target (email-addr) of the relationship.
        description : str
            Description of the relationship.
        """
        email = EmailAddress(
            id=OpenCTIStix2Utils.generate_random_stix_id("email-addr"),
            value=target,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        domain_to_email = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="related-to",
            source_ref=source,
            target_ref=email.id,
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            description=description,
            custom_properties={"x_metis_modified_on_s": self.run_on_s},
        )

        self.bundle += (email, domain_to_email)

    def link_domain_resolves_to(
        self,
        source_id: str,
        target: Union[int, str],
        target_type: EntityType,
        description: str,
    ) -> str:
        """
        Create the `resolves-to` relationship between the `domain-name` and the target.
        The target can either be a `domain-name` or an `ipv4-addr`
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source_id : str
            Id of the source (`domain-name` object)
        target : str or int
            Value of the target of the relationship.
        target_type : str
            Type of the target. The type of the target is created based on this field.
        description : str
            Description of the relationship (e.g. the type (name-server, redirect, etc).

        Returns
        -------
        str
            Id of the newly created target object. This will allow re-using it for other insertions.
        """
        target_obj = (
            DomainName(
                id=OpenCTIStix2Utils.generate_random_stix_id("domain-name"),
                type="domain-name",
                value=target,
                object_marking_refs=TLP_AMBER,
                custom_properties=self.custom_props,
            )
            if target_type == EntityType.DOMAIN_NAME
            else IPv4Address(
                id=OpenCTIStix2Utils.generate_random_stix_id("ipv4-addr"),
                type="ipv4-addr",
                value=DtBuilder.decimal_to_ip(target),
                object_marking_refs=TLP_AMBER,
                custom_properties=self.custom_props,
            )
        )

        self.create_resolves_to(source_id, target_obj.id, description)

        self.bundle.append(target_obj)
        return target_obj.id

    def link_ip_belongs_to_asn(self, source: str, target: int):
        """
        Create the `belongs-to` relationship between the `ipv4-addr` and the `autonomous-system`.
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source : str
            Value of the source (ip) of the relationship.
        target : int
            Value of the target (autonomous-system) of the relationship.
        """
        auto_system = AutonomousSystem(
            id=OpenCTIStix2Utils.generate_random_stix_id("autonomous-system"),
            number=target,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        ip_to_as = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="belongs-to",
            source_ref=source,
            target_ref=auto_system.id,
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            custom_properties={"x_metis_modified_on_s": self.run_on_s},
        )

        self.bundle += (auto_system, ip_to_as)

    def send_bundle(self) -> None:
        """
        Create and send the bundle containing the author and the enrichment entities.

        Note: `allow_custom` must be set to True in order to specify the author of an object.
        """
        self.helper.metric.inc("record_send", 1 + len(self.bundle))
        self.helper.send_stix2_bundle(
            Bundle(objects=[self.author] + self.bundle, allow_custom=True).serialize()
        )
