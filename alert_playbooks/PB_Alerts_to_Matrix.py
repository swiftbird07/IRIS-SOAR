# Alert Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally notify about any alert to a matrix room.
#
# Acceptable Alerts:
#  - All alerts
#
# Gathered Context:
# - None
#
# Actions:
# - Push matrix notification
#
PB_NAME = "PB_Alerts_to_Matrix"
PB_VERSION = "0.1.0"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

CACHE_MAX_LOOKBACK_TIME_MINUTES = 10

import time
import traceback
from typing import Union, List
import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, AuditLog, Alert
from lib.config_helper import Config
import lib.iris_helper as iris_helper
import integrations.matrix_notify as matrix_notify
from lib.generic_helper import add_to_cache, get_from_cache, dict_get, redact_string


def get_highlighted_fields_str(mlog, alert: Alert) -> str:
    """Returns a string containing all highlighted fields from an alert in matrix compatible html format.

    Args:
        alert (Alert): The alert to get the highlighted fields from

    Returns:
        str: The string containing all highlighted fields
    """
    highlighted_fields = alert.highlighted_fields
    if not highlighted_fields or len(highlighted_fields) == 0:
        return ""

    message = ""

    for field in highlighted_fields:
        try:
            value = str(dict_get(alert.raw, field))
            if "host.name" in field:
                continue  # Skip the host.name field as it is already in the message

            # Redact any passwords, tokens, etc.
            value = redact_string(value)

            message += f"<b>{field}</b>: {value}<br><br>"
        except Exception as e:
            mlog.warning(
                f"get_highlighted_fields_str() - Could not add highlighted field '{field}' to message. Skipping. Exception Traceback: {traceback.format_exc()}"
            )

    mlog.debug(f"get_highlighted_fields_str() - Message's highlighted fields: {message}")
    return message


def get_emoji_for_severity(severity: int) -> str:
    if severity >= 0 and severity <= 20:
        return "⚪️"
    elif severity > 20 and severity < 47:
        return "🟢"
    elif severity >= 47 and severity < 73:
        return "🟡"
    elif severity >= 73 and severity < 90:
        return "🟠"
    elif severity >= 90 and severity <= 100:
        return "🔴"
    else:
        return "⍰"


def irsoar_handle_alerts(alerts: Alert, Test: bool = False):
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

    # First load the past matrix messages from cache
    matrix_past_messages = get_from_cache(PB_NAME, "matrix_past_messages", "LIST")

    for alert in alerts:
        if alert.state != "new":
            mlog.info(f"Alert '{alert.name}' is not new. Skipping.")
            continue

        alert: Alert = alert

        # Get 'highlighted fields'
        highlighted_fields = alert.highlighted_fields

        # Get the hostname, source ip and rule name from the alert
        hostname = str(alert.get_host()) if alert.get_host() else None
        source_ip = str(alert.flow.source_ip) if alert.flow and alert.flow.source_ip else None
        rule_name = str(alert.name)  # Should be always available

        mlog.info(f"Alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' received.")

        ## First compare if the cache has an entry for an alert with the same name, host and source ip in the last X minutes
        # If yes, skip the alert
        if matrix_past_messages and len(matrix_past_messages) > 0:
            for past_message in matrix_past_messages:
                if (
                    past_message["hostname"] == hostname
                    and past_message["source_ip"] == source_ip
                    and past_message["rule_name"] == rule_name
                ):
                    mlog.debug(
                        f"Found similar alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' in cache. Now checking time."
                    )
                    # Time check
                    if past_message["timestamp"] > (time.time() - (CACHE_MAX_LOOKBACK_TIME_MINUTES * 60)):
                        mlog.info(
                            f"Alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' received already in the last {str(CACHE_MAX_LOOKBACK_TIME_MINUTES)} minutes. Skipping."
                        )
                        continue
                    else:
                        mlog.debug(
                            f"Alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' received more than {str(CACHE_MAX_LOOKBACK_TIME_MINUTES)} minutes ago. Sending to matrix."
                        )
                else:
                    mlog.debug(
                        f"Alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' not found in cache. Sending to matrix."
                    )

        ## Prepare the alert message to matrix
        mlog.info(f"Sending alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' to matrix.")

        # Get the alerts severity emoji circle
        severity = dict_get(
            alert.raw["kibana.alert.rule.parameters"], "risk_score", -1
        )  # This is not the actual severity from IRIS but the risk score from Elastic SIEM. This is a hacky workaround for now. #TODO: Fix this
        circle = get_emoji_for_severity(severity)

        # Create the message in matrix compatible html format, including the highlighted fields, all wrapped in a big quote for style, including the severity emoji
        # OLD message = f"<blockquote><b>{circle} New Alert from SIEM </b><br><br><b>Hostname:</b> {hostname_str}<br><b>Rule Name:</b> {rule_name}<br><br>{get_highlighted_fields_str(mlog, alert)}</blockquote>"
        message = f"<blockquote><b>{circle} New Alert '{rule_name}' </b><br><br><b>Hostname:</b> {hostname}<br><br><br>{get_highlighted_fields_str(mlog, alert)}</blockquote>"

        mlog.debug(f"Message to send to matrix: {message}")

        ## Send the message to matrix
        config = cfg["integrations"]["matrix_notify"]
        suc = matrix_notify.irsoar_notify(config, message, allow_multiple=True)

        if suc:
            mlog.info(f"Successfully sent alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' to matrix.")

            # Add the message to the cache
            matrix_message = {
                "hostname": hostname,
                "source_ip": source_ip,
                "rule_name": rule_name,
                "timestamp": time.time(),
            }

            add_to_cache(PB_NAME, "matrix_past_messages", "LIST", matrix_message)
            mlog.debug(f"Added alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' to cache.")
        else:
            mlog.error(f"Failed to send alert '{rule_name}' from host '{hostname}' with source ip '{source_ip}' to matrix.")
            return False
