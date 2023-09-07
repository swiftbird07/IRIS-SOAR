# Alert Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally handle all alerts from DFIR-IRIS and make them to a case in IRIS (or add them to an existing one) if there are at least X alerts from the same host.
#
# Acceptable Alerts:
#  - All alerts
#
# Gathered Context:
# - None
#
# Actions:
# - Create IRIS Case if not already done
#
PB_NAME = "PB_Create_Case_for_Multiple_Host_Alerts"
PB_VERSION = "0.1.0"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

from typing import Union, List
import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, AuditLog, Alert
from lib.config_helper import Config
import lib.iris_helper as iris_helper

COUNT_ALERTS_FROM_SAME_HOST = 2


def irsoar_handle_alerts(alerts: Alert):
    """Handles the alerts from DFIR-IRIS.

    Args:
        alerts (Alert): The alert to handle
    """
    # Prepare the logger
    cfg = Config().cfg
    config = cfg["integrations"]["dfir-iris"]
    log_level_file = config["logging"]["log_level_file"]
    log_level_stdout = config["logging"]["log_level_stdout"]
    mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)

    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling alert.")
        return False

    # Create a new list for every alert by the same host
    alerts_by_host = {}
    for alert in alerts:
        alert: Alert = alert

        host = str(alert.get_host())

        if host not in alerts_by_host:
            alerts_by_host[host] = []
        alerts_by_host[host].append(alert)

    case_list = []

    for host in alerts_by_host:
        # Check if there is already a case for the host
        cases = iris_helper.get_cases_by_title(host, partial_match=True)
        if len(cases) > 0:
            mlog.info(f"Found {len(cases)} case(s) for host '{host}'. Adding the alerts to them.")

            # Add the alerts to the case
            for case in cases:
                mlog.info(f"Adding {len(alerts_by_host[host])} alerts to case '{case.case_number}'")
                case: CaseFile = case
                case.alerts.extend(alerts_by_host[host])

                # Add the case to the alerts
                for alert in alerts_by_host[host]:
                    alert: Alert = alert
                    alert.iris_update_state("open")
                    alert.iris_attach_to_case(case.uuid)

                # Add a audit notes to the case
                case.add_note_to_iris(group="IRIS-SOAR Audit", title=f"Added {len(alerts_by_host[host])} alerts to case.", content=f"Added Alerts: {alerts_by_host[host]}")

                # Add a note to the alerts
                for alert in alerts_by_host[host]:
                    alert.add_note_to_iris(alert.case_file, f"Added to case '{case.case_number}'")

            case_list.extend(cases)
            continue  # Skip the rest of the loop

        # For potential new Case: Check if there are enough alerts from the same host
        if len(alerts_by_host[host]) >= COUNT_ALERTS_FROM_SAME_HOST:
            mlog.info(f"Found {len(alerts_by_host[host])} alerts from the same host '{host}'. Creating a case for them.")
            # Create a new case object for the alerts
            case_file = CaseFile(alerts_by_host[host])

            # Add the case to the alerts
            for alert in alerts_by_host[host]:
                alert: Alert = alert
                alert.iris_update_state("open")

                # The first alert hast to be excalaed to a case, the rest will merge into it
                if alert == alerts_by_host[host][0]:
                    case_file.uuid = alert.iris_excalate_to_case()
                else:
                    alert.iris_attach_to_case(case_file.uuid)

            # Add a audit notes to the case
            case_file.add_note_to_iris(
                group="IRIS-SOAR Audit", title=f"Created a case for {len(alerts_by_host[host])} alerts from the same host '{host}'.", content=f"Initial Alerts: {alerts_by_host[host]}"
            )

            # Add a note to the alerts
            for alert in alerts_by_host[host]:
                alert.add_note_to_iris(alert.case_file, f"Added to case '{case_file.uuid}'")

            case_list.append(case_file)

        else:
            mlog.info(f"Found {len(alerts_by_host[host])} alerts from the same host '{host}'. Not enough to create a case.")

    return case_list
