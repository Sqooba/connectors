# -*- coding: utf-8 -*-
"""VMRay connector main file."""

from pathlib import Path
from vmray import VMRayConnector

if __name__ == "__main__":
    config_file = Path(__file__).parent.resolve() / "config.yml"
    connector = VMRayConnector(config_file)
    connector.start()
