# -*- coding: utf-8 -*-
"""Record class to store a relation between a domain and another entity."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import validators

from .constants import (
    DOMAIN_FIELDS,
    EntityType,
    IP_FIELDS,
)


@dataclass
class Record:
    """Class to store a record from DNSDB."""

    source: str
    destination: str
    first_date: datetime
    last_date: datetime
    rtype: str
    description: str
    has_conflict: bool = False

    def set_conflict(self):
        """
        Set the record as having a conflict.
        """
        self.has_conflict = True

    def update_all_time_first(self, new_date: datetime):
        """
        Take the smaller date.

        Parameters
        ----------
        new_date : datetime
            New date to compare.
        """
        if new_date < self.first_date:
            self.first_date = new_date

    def update_all_time_last(self, new_date: datetime):
        """
        Take the higher date.

        Parameters
        ----------
        new_date : datetime
            New date to compare.
        """
        if new_date > self.last_date:
            self.last_date = new_date

    def get_destination_type(self) -> Optional[EntityType]:
        """
        Get the entity type of the record and check the validity.

        If not valid, returns None.

        Returns
        -------
        EntityType, optional
            Type of the destination.
        """
        if self.rtype in DOMAIN_FIELDS and validators.domain(self.destination):
            return EntityType.DOMAIN_NAME
        if self.rtype in IP_FIELDS and validators.ipv4(self.destination):
            return EntityType.IPV4
        logging.warning(f"Record {self} is not valid.")
        return None
