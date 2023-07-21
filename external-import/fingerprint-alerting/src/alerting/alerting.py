# -*- coding: utf-8 -*-
"""Alerting module."""
import os
import sys
import time
from datetime import datetime
from typing import Any, Mapping, Optional

import vt
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .builder import AlertingBuilder


class Alerting:
    _DEFAULT_AUTHOR = "Fingerprint Alerting"

    # Default run interval
    _CONNECTOR_RUN_INTERVAL_SEC = 60
    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        author = self.helper.api.identity.create(
            name=self._DEFAULT_AUTHOR,
            type="Organization",
            description="Fingerprint alerting if a misp observable is found on VirusTotal",
            confidence=self.helper.connect_confidence_level,
        )

        api_key = get_config_variable(
            "FINGERPRINT_ALERTING_VIRUSTOTAL_API_KEY",
            ["fingerprint_alerting", "virustotal_api_key"],
            config,
        )
        vt_client = vt.Client(api_key)

        self.interval_sec = get_config_variable(
            "FINGERPRINT_ALERTING_INTERVAL_SEC",
            ["fingerprint_alerting", "interval_sec"],
            config,
        )

        last_n_days = get_config_variable(
            "FINGERPRINT_ALERTING_CHECK_LAST_N_DAYS",
            ["fingerprint_alerting", "check_last_n_days"],
            config,
            isNumber=True,
        )

        first_submission_n_days = get_config_variable(
            "FINGERPRINT_ALERTING_FIRST_SUBMISSION_N_DAYS",
            ["fingerprint_alerting", "first_submission_n_days"],
            config,
            isNumber=True,
        )

        label = get_config_variable(
            "FINGERPRINT_ALERTING_LABEL",
            ["fingerprint_alerting", "label"],
            config,
        )

        exclude = get_config_variable(
            "FINGERPRINT_ALERTING_EXCLUDE",
            ["fingerprint_alerting", "exclude"],
            config,
        )

        self.builder = AlertingBuilder(
            vt_client,
            self.helper,
            author,
            self._DEFAULT_AUTHOR,
            label,
            exclude,
            last_n_days,
            first_submission_n_days,
        )

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _initiate_work(self, timestamp: int) -> str:
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = "Fingerprint Alerting run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.log_info(f"[Fingerprint Alerting] workid {work_id} initiated")
        return work_id

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.log_info("Fingerprint Alerting connector clean run")
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _get_next_interval(
        self, run_interval: int, timestamp: int, last_run: int
    ) -> int:
        """Get the delay for the next interval."""
        next_run = self._get_interval() - (timestamp - last_run)
        return min(run_interval, next_run)

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

    def run(self):
        """Run Fingerprint Alerting."""
        self.helper.log_info("Starting Fingerprint Alerting Connector...")

        while True:
            self.helper.log_info("Running Fingerprint Alerting connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                self.helper.log_info(f"Connector interval sec: {run_interval}")
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()
                self.helper.log_info(
                    f"[Fingerprint Alerting] loaded state: {current_state}"
                )

                last_run = self._get_state_value(
                    current_state,
                    self._STATE_LATEST_RUN_TIMESTAMP,
                )
                if self._is_scheduled(last_run, timestamp):
                    self.helper.log_info(
                        f"[Fingerprint Alerting] starting run at: {current_state}"
                    )
                    new_state = current_state.copy()

                    self.builder.process()
                    if len(self.builder.bundle) > 0:
                        work_id = self._initiate_work(timestamp)
                        self.builder.send_bundle(work_id)
                    else:
                        self.helper.log_debug("No bundle to send")

                    # Set the new state
                    new_state[
                        self._STATE_LATEST_RUN_TIMESTAMP
                    ] = self._current_unix_timestamp()
                    self.helper.log_info(
                        f"[Fingerprint Alerting] Storing new state: {new_state}"
                    )
                    self.helper.set_state(new_state)
                else:
                    run_interval = self._get_next_interval(
                        run_interval, timestamp, last_run
                    )
                    self.helper.log_info(
                        f"[Fingerprint Alerting] Connector will not run, next run in {run_interval} seconds"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Fingerprint Alerting connector stop")
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            self._sleep(delay_sec=run_interval)


if __name__ == "__main__":
    try:
        alerting = Alerting()
        alerting.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
