# -*- coding: utf-8 -*-
"""VMRay connector RelationshipRef class."""

from dataclasses import dataclass
from typing import Optional

from ..utils.constants import RelationshipType


@dataclass
class RelationshipRef:
    """
    This class represent the needed values to build a STIX relationship.

    Parameters
    ----------
    source: str
        * The source id used to build the SRO
    target: str
        * The target id used to build the SRO
    relationship_type: Optional[str]
        * The relationship_type used to build the SRO, set to 'related-to' if
        the type is not explicitly passed when creating the object.
    description: str
        * The description field used to build the SRO
    """

    source: str
    target: str
    relationship_type: Optional[str]
    description: str = "VMRay: sample to IOC"

    def __post_init__(self):
        self.relationship_type = (
            self.relationship_type
            if self.relationship_type
            else RelationshipType.RELATED.value
        )
