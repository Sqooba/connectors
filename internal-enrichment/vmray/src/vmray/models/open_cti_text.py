# -*- coding: utf-8 -*-
"""VMRay connector OpenCtiText class."""


from stix2 import CustomObservable, properties


@CustomObservable(
    "x-opencti-text",
    [
        ("value", properties.StringProperty(required=True)),
        ("object_marking_refs", properties.ReferenceProperty(valid_types="tlp")),
    ],
)
class OpenCtiText:
    """
    Wrapper class for CustomObservable. This class is decorate with CustomObservable's metadata.
    The CustomObservable decorator add the fields needed to represent a x-opencti-text.
    """
