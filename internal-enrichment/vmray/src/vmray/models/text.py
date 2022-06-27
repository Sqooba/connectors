# -*- coding: utf-8 -*-
"""VMRay connector Text class."""
from stix2 import CustomObservable, properties


@CustomObservable(
    "text",
    [
        ("value", properties.StringProperty(required=True)),
        ("object_marking_refs", properties.ReferenceProperty(valid_types="tlp")),
    ],
)
class Text:
    """
    Wrapper class for CustomObservable. This class is decorated with CustomObservable's metadata.
    The CustomObservable decorator add the fields needed to represent a Text object.
    """
