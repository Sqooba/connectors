# -*- coding: utf-8 -*-
"""ElasticSearch client module."""

from typing import Any
from elasticsearch import Elasticsearch
from .constants import EntityType

# Custom type to simulate a JSON format.
JSONType = dict[str, Any]


class EsClient:
    """ElasticSearch client."""

    # Mapping for the fields in ES.
    MAPPING = {EntityType.STIXFILE: "sample_details.sha256_hash"}

    def __init__(self, endpoint: str, index: str) -> None:
        """Initialize ElasticSearch client."""
        self.client = Elasticsearch(endpoint)
        self.index = index

    def search(self, sha: str, stixFile: EntityType) -> JSONType:
        """
        Search for the given SHA in all fields named sample_details.sha256_hash.

        A CyberObservable can be:
            - Stix-File

        Parameters
        ----------
        sha: str
           The stixFile sha 256 field (sample_details.sha256_hash)
        stixFile : EntityType
           The type of entity that will be searched

        Returns
        -------
        JSON
            The documents matching the given stixFile, if any.

        """
        return self.client.search(
            index=self.index,
            _source=True,
            query={
                "simple_query_string": {
                    "fields": [self.MAPPING[stixFile]],
                    "query": sha,
                }
            },
        )
