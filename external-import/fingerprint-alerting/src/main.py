"""Fingerprint alerting main file."""
from alerting import Alerting

if __name__ == "__main__":
    connector = Alerting()
    connector.run()
