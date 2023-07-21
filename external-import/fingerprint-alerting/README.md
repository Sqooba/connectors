# OpenCTI Fingerprint alerting

From reports with a given label, check if the observables of the report are found on VirusTotal. If so, check if there are communicating with recent files (first submission date more recent than one month by default)

The connector runs periodically and check the report created in the last N days to check if observable have appeared on VirusTotal.
