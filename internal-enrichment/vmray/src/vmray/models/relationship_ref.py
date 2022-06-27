# -*- coding: utf-8 -*-
"""VMRay connector RelationshipRef class."""

from dataclasses import dataclass
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
    relationship_type: RelationshipType = RelationshipType.RELATED.value
    description: str = "VMRay: sample to IOC"

    def __eq__(self, other):
        return (self.source, self.target) == (other.source, other.target)

    def __hash__(self):
        return hash((self.source, self.target))
