# OpenCTI DomainTools Connector

The OpenCTI DomainTools connector can be used to import knowledge from the [DomainTools API](https://www.domaintools.com/). 

The connector enrich the domain with other domains, ips, etc. 

## Configuration

The connector can be configured with the following variables: 

| Config Parameter          | Docker env var                        | Default    | Description                                                      |
|---------------------------|---------------------------------------|------------|------------------------------------------------------------------|
| `api_username`            | `DOMAINTOOLS_API_USERNAME`            | `ChangeMe` | The username required for the authentication on DomainTools API. |
| `api_key`                 | `DOMAINTOOLS_API_KEY`                 | `ChangeMe` | The password required for the authentication on DomainTools API. |
| `app_kibana_redirect_url` | `DOMAINTOOLS_APP_KIBANA_REDIRECT_URL` | `ChangeMe` | The url for the kibana-redirect tool.                            |
