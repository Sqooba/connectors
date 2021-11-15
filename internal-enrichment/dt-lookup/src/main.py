# -*- coding: utf-8 -*-
"""DT-Lookup connector main file."""

from dtlookup import DTLookupConnector


if __name__ == "__main__":
    connector = DTLookupConnector()
    connector.start()
