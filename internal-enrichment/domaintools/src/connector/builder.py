# -*- coding: utf-8 -*-
"""Builder for DT-Lookup."""

from datetime import datetime
import json
from typing import Any, Optional, Union
import validators

from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils
from stix2 import (
    AutonomousSystem,
    Bundle,
    DomainName,
    EmailAddress,
    Identity,
    IPv4Address,
    Note,
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
    ):
        """Initialize DtBuilder."""
        self.helper = helper
        self.author = author

        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": author["id"],
        }

        self.bundle: list[
            Union[AutonomousSystem, DomainName, EmailAddress, IPv4Address, Relationship]
        ] = []

    def reset_score(self):
        """Reset the score used."""
        if "x_opencti_score" in self.custom_props:
            self.custom_props.pop("x_opencti_score")

    def set_score(self, score: int):
        """
        Set the score for the observable.

        Parameters
        ----------
        score : int
            Score to use as `x_opencti_score`
        """
        self.custom_props["x_opencti_score"] = score

    def create_domain(self, domain: str) -> Optional[str]:
        """
        Create a domain object with the author and custom properties.

        Parameters
        ----------
        domain : str
            Domain to create.

        Returns
        -------
        str
            Id of the inserted domain or None if the domain is invalid.
        """
        if not validators.domain(domain):
            self.helper.metric_inc("error_count")
            self.helper.log_warning(
                f"[DomainTools] domain {domain} is not correctly "
                "formatted. Skipping."
            )
            return None
        domain_obj = DomainName(
            id=OpenCTIStix2Utils.generate_random_stix_id("domain-name"),
            type="domain-name",
            value=domain,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(domain_obj)
        return domain_obj.id

    def create_email(self, email: str) -> Optional[str]:
        """
        Create an email object with the author and custom properties.

        Parameters
        ----------
        email : str
            Email to create.

        Returns
        -------
        str
            Id of the inserted email or None if the domain is invalid.
        """
        if not validators.email(email):
            self.helper.metric_inc("error_count")
            self.helper.log_warning(
                f"[DomainTools] email {email} is " "not correctly formatted. Skipping."
            )
            return None
        email_obj = EmailAddress(
            id=OpenCTIStix2Utils.generate_random_stix_id("email-addr"),
            value=email,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(email_obj)
        return email_obj.id

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
        info = {
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
            contact_information=json.dumps(info),
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(identity)
        return identity.id

    def create_ipv4(self, ip: str) -> Optional[str]:
        """
        Create an ip object with the author and custom properties.

        Parameters
        ----------
        ip : str
            Ip to create.

        Returns
        -------
        str
            Id of the inserted ip or None if the ip is invalid.
        """
        if not validators.ipv4(ip):
            self.helper.metric_inc("error_count")
            self.helper.log_warning(
                f"[DomainTools] ip {ip} is not correctly " "formatted. Skipping."
            )
            return None
        ip_obj = IPv4Address(
            id=OpenCTIStix2Utils.generate_random_stix_id("ipv4-addr"),
            type="ipv4-addr",
            value=ip,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        self.bundle.append(ip_obj)
        return ip_obj.id

    def create_resolves_to(
        self,
        source_id: str,
        target_id: str,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> str:
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
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str, optional
            Description of the relationship (e.g. the type (name-server, redirect, etc.).

        Returns
        -------
        str
            Id of created relationship.
        """
        kwargs = {
            "created_by_ref": self.author,
            "confidence": self.helper.connect_confidence_level,
            "description": description,
        }
        if start_date != "" and end_date != "":
            kwargs |= {"start_time": start_date, "stop_time": end_date}
        domain_to_target = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="resolves-to",
            source_ref=source_id,
            target_ref=target_id,
            **kwargs,
        )

        self.bundle.append(domain_to_target)
        return domain_to_target

    def create_related_to(
        self,
        source_id: str,
        target_id: str,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> str:
        """
        Create the `related-to` relationship between the source and the target.

        Parameters
        ----------
        source_id : str
            Id of the source.
        target_id : str
            Id of the target.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str
            Description of the relationship.

        Returns
        -------
        str
            Id of created relationship.
        """
        kwargs = {
            "created_by_ref": self.author,
            "confidence": self.helper.connect_confidence_level,
            "description": description,
        }
        if start_date != "" and end_date != "":
            kwargs |= {"start_time": start_date, "stop_time": end_date}
        rel = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="related-to",
            source_ref=source_id,
            target_ref=target_id,
            **kwargs,
        )

        self.bundle.append(rel)
        return rel

    def create_note(
        self,
        source_id: str,
        abstract: str,
        content: str,
    ):
        """
        Create a note for the observable and add it to the bundle.

        Parameters
        ----------
        source_id : str
            Standard id of the observable receiving the Note.
        abstract : str
            Abstract for the note.
        content : str
            Content for the note.
        """
        note = Note(
            id=OpenCTIStix2Utils.generate_random_stix_id("note"),
            created_by_ref=self.author,
            confidence=self.helper.connect_confidence_level,
            object_marking_refs=TLP_AMBER,
            abstract=abstract,
            content=content,
            object_refs=[source_id],
        )
        self.bundle.append(note)

    def link_domain_related_to_email(
        self,
        source: str,
        target: str,
        start_date: datetime,
        end_date: datetime,
        description: str,
    ):
        """
        Create the `related-to` relationship between the `domain-name` and the `email-addr`.
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source : str
            Value of the source (domain-name) of the relationship.
        target : str
            Value of the target (email-addr) of the relationship.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str
            Description of the relationship.
        """
        email_id = self.create_email(target)
        if email_id is not None:
            kwargs = {
                "created_by_ref": self.author,
                "confidence": self.helper.connect_confidence_level,
                "description": description,
            }
            if start_date != "" and end_date != "":
                kwargs |= {"start_time": start_date, "stop_time": end_date}
            domain_to_email = Relationship(
                id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                relationship_type="related-to",
                source_ref=source,
                target_ref=email_id,
                **kwargs,
            )

            self.bundle.append(domain_to_email)

    def link_domain_resolves_to(
        self,
        source_id: str,
        target: str,
        target_type: EntityType,
        start_date: datetime,
        end_date: datetime,
        description: Optional[str] = None,
    ) -> Optional[tuple[str, str]]:
        """
        Create the `resolves-to` relationship between the `domain-name` and the target.
        The target can either be a `domain-name` or an `ipv4-addr`
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source_id : str
            Id of the source (`domain-name` object)
        target : str
            Value of the target of the relationship.
        target_type : str
            Type of the target. The type of the target is created based on this field.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        description : str, optional
            Description of the relationship (e.g. the type (name-server, redirect, etc).

        Returns
        -------
        Tuple of two str
            Id of the relationship and the newly created target object or None if invalid.
            This will allow re-using it for other insertions.
        """
        target_obj = (
            self.create_domain(target)
            if target_type == EntityType.DOMAIN_NAME
            else self.create_ipv4(target)
        )
        if target_obj is not None:
            rel = self.create_resolves_to(
                source_id, target_obj, start_date, end_date, description
            )
            return rel, target_obj
        return None

    def link_ip_belongs_to_asn(
        self, source: str, target: int, start_date: datetime, end_date: datetime
    ):
        """
        Create the `belongs-to` relationship between the `ipv4-addr` and the `autonomous-system`.
        The created objects are saved into the `bundle` object of the class.

        Parameters
        ----------
        source : str
            Value of the source (ip) of the relationship.
        target : int
            Value of the target (autonomous-system) of the relationship.
        start_date : datetime
            Starting date for the relationship.
        end_date : datetime
            Ending date for the relationship.
        """
        auto_system = AutonomousSystem(
            id=OpenCTIStix2Utils.generate_random_stix_id("autonomous-system"),
            number=target,
            object_marking_refs=TLP_AMBER,
            custom_properties=self.custom_props,
        )

        kwargs = {
            "created_by_ref": self.author,
            "confidence": self.helper.connect_confidence_level,
        }
        if start_date != "" and end_date != "":
            kwargs |= {"start_time": start_date, "stop_time": end_date}

        ip_to_as = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="belongs-to",
            source_ref=source,
            target_ref=auto_system.id,
            **kwargs,
        )

        self.bundle += (auto_system, ip_to_as)

    def send_bundle(self) -> None:
        """
        Create and send the bundle containing the author and the enrichment entities.

        Note: `allow_custom` must be set to True in order to specify the author of an object.
        """
        self.helper.metric_inc("record_send", 1 + len(self.bundle))
        self.helper.send_stix2_bundle(
            Bundle(objects=[self.author] + self.bundle, allow_custom=True).serialize(),
            allow_custom=True,
            update=True,
        )
