# -*- coding: utf-8 -*-
"""rcATT connector main file."""

from rcatt import RcAttConnector

if __name__ == "__main__":
    connector = RcAttConnector()
    connector.start()
