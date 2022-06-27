# -*- coding: utf-8 -*-
"""VMRay RelationshipRef test file."""

import sys

sys.path.append("..")
from src.vmray.models.relationship_ref import RelationshipRef
from src.vmray.utils.constants import RelationshipType


class TestRelationshipRef:
    def test_duplicate(self):
        """
        Test to create a set of object RelationshipRef, the result should be equal to the compared values
        """
        expected = set()
        rels = [
            RelationshipRef("source_01", "target_01", "resolve"),
            RelationshipRef("source_01", "target_01", "resolve"),
            RelationshipRef("source_02", "target_02", None),
            RelationshipRef("source_02", "target_02", "resolve"),
            RelationshipRef("source_03", "target_03", "resolve"),
            RelationshipRef("source_03", "target_03", "resolve"),
        ]
        for rel in rels:
            expected.add(rel)
        # Test the set length
        assert len(expected) == 3

    def test_default_values(self):
        """
        Test RelationshipRef dataclass's default value, the result should be equal to the compared values
        """
        default_description = "VMRay: sample to IOC"
        test_description = "test_description"
        test_value_00 = RelationshipRef(
            "source_01", "target_01", RelationshipType.RESOLVES.value
        )
        test_value_01 = RelationshipRef(
            "source_01", "target_01", description=test_description
        )

        assert RelationshipType.RESOLVES.value == test_value_00.relationship_type
        assert default_description == test_value_00.description
        assert test_description == test_value_01.description
        assert RelationshipType.RELATED.value == test_value_01.relationship_type
