# OpenCTI DomainTools Connector

The OpenCTI DomainTools connector can be used to import knowledge from the [DomainTools API](https://www.domaintools.com/) and the [DNS DB API](https://pypi.org/project/dnsdb2/).

The connector enrich the domain with other domains, ip, etc. 

## Configuration

The connector can be configured with the following variables: 

| Config Parameter   | Docker env var                 | Default    | Description                                          |
|--------------------|--------------------------------|------------|------------------------------------------------------|
| `api_username`     | `DOMAINTOOLS_API_USERNAME`     | `ChangeMe` | The username required for the authentication.        |
| `api_key`          | `DOMAINTOOLS_API_KEY`          | `ChangeMe` | The password required for the authentication.        |
| `app_api_base_url` | `DOMAINTOOLS_APP_API_BASE_URL` | `ChangeMe` | Base url for uploading file to ES using custom API.  |
| `app_sso_base_url` | `DOMAINTOOLS_APP_SSO_BASE_URL` | `ChangeMe` | Base url for SSO authentication in the custom API.   |
| `app_realm_name`   | `DOMAINTOOLS_APP_REALM_NAME`   | `ChangeMe` | Realm name for SSO authentication in the custom API. |
| `app_client_id`    | `DOMAINTOOLS_APP_CLIENT_ID`    | `ChangeMe` | Client ID for SSO authentication in the custom API.  |
| `app_user`         | `DOMAINTOOLS_APP_USER`         | `ChangeMe` | User for SSO authentication in the custom API.       |
| `app_password`     | `DOMAINTOOLS_APP_PASSWORD`     | `ChangeMe` | Password for SSO authentication in the custom API.   |
| `app_base_path`    | `DOMAINTOOLS_APP_BASE_PATH`    | `ChangeMe` | Base path for uploading file in the custom API.      |
