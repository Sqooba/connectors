# -*- coding: utf-8 -*-
"""ElasticSearch client module."""

from typing import Any, Dict

from elasticsearch import Elasticsearch

from .constants import EntityType

# Custom type to simulate a JSON format.
JSONType = Dict[str, Any]


class EsClient:
    """ElasticSearch client."""

    # Mapping for the fields in ES.
    MAPPING = {EntityType.STIXFILE: "sample_details.sha256_hash"}

    def __init__(self, endpoint: str, index: str) -> None:
        """Initialize ElasticSearch client."""
        self.client = Elasticsearch(endpoint)
        self.index = index

    def search(self, sha: str, stix_file: EntityType) -> JSONType:
        """
        Search for the given SHA in all fields named sample_details.sha256_hash.

        A CyberObservable can be:
            - Stix-File

        Parameters
        ----------
        sha: str
           The stixFile sha 256 field (sample_details.sha256_hash)
        stix_file : EntityType
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
                    "fields": [self.MAPPING[stix_file]],
                    "query": sha,
                }
            },
        )
