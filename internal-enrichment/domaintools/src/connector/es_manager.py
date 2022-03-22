# -*- coding: utf-8 -*-
"""ElasticSearch manager."""

import calendar
from datetime import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Optional

from keycloak import KeycloakOpenID
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class ESManager:
    """ESManager handles all operations for elasticsearch."""

    _INDEX = "pdns_record"

    def __init__(
        self,
        base_path: Path,
        base_url: str,
        sso_url: str,
        realm_name: str,
        client_id: str,
        user: str,
        password: str,
        metrics: Optional[dict[str, Any]] = None,
    ):
        """
        Initialization of the ElasticSearch manager.

        Parameters
        ----------
        base_path : Path
            Base path for the file to trigger.
        base_url : str
            Base url for the app API.
        sso_url : str
            SSO url to retrieve the token used for the authentication.
        realm_name : str
            Realm name for SSO.
        client_id : str
            Client id for SSO.
        user : str
            User for SSO.
        password : str
            Password for SSO.
        """
        self.base_path = base_path
        self.base_url = base_url
        self.sso_url = sso_url
        self.realm_name = realm_name
        self.client_id = client_id
        self.user = user
        self.password = password
        self.metrics = metrics
        self.actions = ""  # Batch of records to insert using the bulk api.

    @staticmethod
    def _create_id(*args) -> str:
        """
        Create an id for ElasticSearch using all the provided args.

        Parameters
        ----------
        args : list of str
            Args used to create the hash.

        Returns
        -------
        str
            MD5 hash based on the given fields.
        """
        return hashlib.md5("".join(args).encode()).hexdigest()

    def _get_token(self):
        """
        Request a token for SSO.

        Returns
        -------
        dict
            Token for the SSO.
        """
        # Configure client
        keycloak_openid = KeycloakOpenID(
            server_url=f"{self.sso_url}/auth/",
            client_id=self.client_id,
            realm_name=self.realm_name,
            verify=False,
        )

        token = keycloak_openid.token(self.user, self.password, grant_type="password")
        logging.debug("SSO token retrieved successfully.")
        return token

    @staticmethod
    def datetime_to_timestamp(datetime_value: datetime) -> int:
        """Convert datetime to Unix timestamp."""
        # Use calendar.timegm because the time.mktime assumes that the input is in your
        # local timezone.
        return calendar.timegm(datetime_value.timetuple()) * 1000

    def _query(self, route: str, data: str, mode: str):
        """
        Execute a POST query to the Metis api.

        Retries are done if the query fails.

        Parameters
        ----------
        route : str
            Route to query.
        data : str
            Data for the POST request.
        mode : str
            Mode of the request (file / trigger).

        Returns
        -------
        JSON or None
            The result of the query, as JSON or None in case of failure.
        """
        token = self._get_token()
        headers = {
            "Authorization": f"Bearer {token['access_token']}",
            "accept": "application/json",
        }
        if mode == "file":
            headers["Content-Type"] = "multipart/form-data"
        if mode == "trigger":
            headers["Content-Type"] = "application/json"

        logging.debug(f"Headers: {headers}")
        # Configure the adapter for the retry strategy.
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("http://", adapter)
        error = False
        response = None
        try:
            logging.debug(f"Sending {data}")
            response = http.post(
                f"{self.base_url}{route}", data=data, headers=headers, verify=False
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            logging.error(f"Http error: {errh} ({response.text})")
            error = True
        except requests.exceptions.ConnectionError as errc:
            logging.error(f"Error connecting: {errc}")
            error = True
        except requests.exceptions.Timeout as errt:
            logging.error(f"Timeout error: {errt}")
            error = True
        except requests.exceptions.RequestException as err:
            logging.error(f"Something else happened: {err}")
            error = True
        else:
            return response
        finally:
            if error and self.metrics is not None:
                self.metrics["client_error_count"].inc()
        return None

    def add_to_batch(
        self,
        source: str,
        destination: str,
        rtype: str,
        first_date: datetime,
        last_date: datetime,
    ):
        """
        Add a record to the next batch to be inserted.

        Parameters
        ----------
        source : str
            Source (domain name) of the record.
        destination : str
            Destination of the record.
        rtype : str
            Type of the record.
        first_date : datetime
            Starting date for the relationship.
        last_date : datetime
            Ending date for the relationship.
        """
        new_id = ESManager._create_id(
            source, destination, rtype, str(first_date), str(last_date)
        )
        self.actions += f'{json.dumps({"index": {"_index": self._INDEX, "_id": new_id}}, default=str)}\n'
        record = json.dumps(
            {
                "source": source,
                "destination": destination,
                "type": rtype,
                "first_date": self.datetime_to_timestamp(first_date),
                "last_date": self.datetime_to_timestamp(last_date),
                "duration_seconds": (last_date - first_date).total_seconds(),
            },
            default=str,
        )
        self.actions += f"{record}\n"

    def bulk_insert(self):
        """Bulk insert of all the pending actions."""
        # Save the actions to HDFS using the API.
        now = datetime.now().strftime("%Y%m%d%H%M%s")

        destination = f"domaintools-connector-{now}"
        logging.info(f"Saving file to {destination}")
        if self.actions == "":
            logging.info(f"No file to send to the API.")
            return
        res = self._query(
            f"/api/v1/file/{destination}",
            self.actions,
            mode="file",
        )
        logging.info(res)

        # Trigger the ingestion of the files in ES.
        logging.info("Trigger the ingestion.")
        res = self._query(
            "/api/v1/control/pipelines/trigger",
            json.dumps(
                {
                    "pipelineId": "external-indexing",
                    "uri": f"{self.base_path / destination}",
                }
            ),
            mode="trigger",
        )
        logging.info(res)
        self.actions = []
