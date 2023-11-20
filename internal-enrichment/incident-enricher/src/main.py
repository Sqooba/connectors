# -*- coding: utf-8 -*-
"""Incident enricher connector main file."""

import sys
import time

from enricher import IncidentEnricherConnector

if __name__ == "__main__":
    try:
        connector = IncidentEnricherConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
