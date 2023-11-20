# OpenCTI IncidentEnricher connector

The OpenCTI IncidentEnricher connector can be used to enrich the observables linked to an incident.

The connectors to use for the enrichment, and on which entity type are defined in the configuration file.

Example of configuration:

```
enrichers:
  connectors:
    - name: "DomainTools"
      types: [Domain-Name]
    - name: VirusTotal
      types: [StixFile, IPv4-Addr]
```

With this configuration example, the connector `VirusTotal` will enrich `StixFile` and `IPv4-Addr` linked to the incident and the connector `DomainTools` will enrich the `Domain-Name`.

This configuration only works when using the configuration file, and not when using environment variable. If you want to use this with Kubernetes, you need to define a ConfigMap containing the `enricher` part of the configuration.

See the `config.yml.sample` example file for more details.

---

*Note*: in the near future, this might be achievable using playbooks.
