# -*- coding: utf-8 -*-
"""ElasticSearch client module."""

import logging
from typing import Any

from elasticsearch import Elasticsearch

from .constants import EntityType

logger = logging.getLogger(__name__)

# Custom type to simulate a JSON format.
JSONType = dict[str, Any]


class EsClient:
    """ElasticSearch client."""

    # Mapping for the fields in ES.
    MAPPING = {
        EntityType.AUTONOMOUS_SYSTEM: "autonomousSystem",
        EntityType.DOMAIN_NAME: "domain",
        EntityType.EMAIL_ADDRESS: "emailAddress",
        EntityType.IPV4: "ip",
    }

    def __init__(self, endpoint: str, index: str) -> None:
        """Initialize ElasticSearch client."""
        # Drop the ending slash if present.
        self.client = Elasticsearch(endpoint)
        self.index = index

    def search(self, observable: str, obs_type: EntityType) -> JSONType:
        """
        Search for the given CyberObservable in all fields.

        A CyberObservable can be:
            - AutonomousSystem
            - DomainName
            - EmailAddr
            - Ipv4Addr

        Parameters
        ----------
        observable : str
            Observable to look for.
        obs_type : EntityType
            The type of the observable used for the query.

        Returns
        -------
        JSON or None
            The documents matching the given observable, if any.

        """
        return self.client.search(
            index=self.index,
            _source="raw",
            query={
                "simple_query_string": {
                    "fields": [self.MAPPING[obs_type]],
                    "query": observable,
                }
            },
        )
