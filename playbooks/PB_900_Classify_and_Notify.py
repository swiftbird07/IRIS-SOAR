# Playbook for Z-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by Z-SOAR
# It is used to general classify and notify the user about a detection.
#
# Acceptable Detections:
#  - All detections
#
# Gathered Context:
# - None
#
# Actions:
# - Set priority of ticket
# - Notify user
#
PB_NAME = "PB_900_Classify_and_Notify"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

TICKET_URL_PATH = "/otrs/index.pl?Action=AgentTicketZoom;TicketID="  # The path to the ticket in the OTRS web interface

import ipaddress
from typing import Union, List

import lib.logging_helper as logging_helper
from lib.class_helper import DetectionReport, ContextProcess, AuditLog, Detection, ContextThreatIntel, DNSQuery, HTTP
from lib.config_helper import Config
from lib.generic_helper import cast_to_ipaddress, format_results, is_local_tld

from integrations.matrix_notify import zs_notify
from integrations.znuny_otrs import zs_add_note_to_ticket, zs_get_ticket_by_number, zs_set_ticket_priority

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["matrix_notify"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["matrix_notify"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def zs_can_handle_detection(detection_report: DetectionReport) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        detection_report (DetectionReport): The detection report

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    # Check if any of the detecions of the detection report is an Elastic Alert
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling anything.")
        return False

    # Check if there is already a ticket for the detection report
    try:
        ticket_number = detection_report.get_ticket_number()
    except ValueError:
        mlog.info(f"Playbook '{PB_NAME}' cannot handle detection report '{detection_report.uuid}' as there is no ticket for it.")
        return False
    return True


def zs_handle_detection(detection_report: DetectionReport, TEST=False) -> DetectionReport:
    """Handles the detection.

    Args:
        detection_report (DetectionReport): The detection report
        TEST (bool): True if the playbook is run in test mode, False if not

    Returns:
        DetectionReport: The updated detection report
    """
    # Get all the indicators
    cfg = Config().cfg
    integration_config = cfg["integrations"]["matrix_notify"]
    mlog.info(f"Handling detection report '{detection_report.uuid}'")
    init_action = AuditLog(
        PB_NAME,
        0,
        "Getting detection report severity",
        "Started handling detection report by getting the highest severity of all detections.",
    )
    detection_report.update_audit(init_action, mlog)

    # Get the highest severity of all detections
    highest_severity = 0
    for detection in detection_report.detections:
        if detection.severity > highest_severity:
            highest_severity = detection.severity
    detection_report.update_audit(
        init_action.set_successful(f"Got the highest severity of all detections. Severity: {highest_severity}"), mlog
    )

    # Set the priority of the ticket
    current_action = AuditLog(
        PB_NAME,
        1,
        "Setting ticket priority",
        "Setting the priority of the ticket based on the highest severity of all detections.",
    )
    detection_report.update_audit(current_action, mlog)

    # Get the ticket
    ticket_number = detection_report.get_ticket_number()
    ticket = zs_get_ticket_by_number(ticket_number)
    if ticket == None:
        mlog.error(f"Could not get ticket '{ticket_number}'")
        detection_report.update_audit(current_action.set_failed(f"Could not get ticket '{ticket_number}'"), mlog)
        return detection_report

    # Set the priority. Severity is a value between 0 and 100. Priority is a string with the values "1 very high", "2 high", "3 normal", "4 low", "5 very low":
    if highest_severity == 0:
        priority = "5 very low"
    elif highest_severity <= 25:
        priority = "4 low"
    elif highest_severity <= 50:
        priority = "3 normal"
    elif highest_severity <= 75:
        priority = "2 high"
    else:
        priority = "1 very high"
    mlog.info(f"Setting priority of ticket '{ticket_number}' to '{priority}'")
    if TEST == False:
        if zs_set_ticket_priority(ticket_number, priority) == False:
            mlog.error(f"Could not set priority of ticket '{ticket_number}' to '{priority}'")
            detection_report.update_audit(
                current_action.set_failed(f"Could not set priority of ticket '{ticket_number}' to '{priority}'"), mlog
            )
            return detection_report
    detection_report.update_audit(
        current_action.set_successful(f"Set priority of ticket '{ticket_number}' to '{priority}'"), mlog
    )

    # Notify the user
    current_action = AuditLog(PB_NAME, 2, "Notifying user", "Notifying the user about the detection.")
    detection_report.update_audit(current_action, mlog)
    ticket_url = cfg["integrations"]["znuny_otrs"]["url"]
    ticket_url += TICKET_URL_PATH

    message = (
        "⚠️ New Ticket that requires user interaction: [Priority: "
        + str(priority)
        + "] ["
        + ticket_title
        + "]({ticket_url}"
        + str(ticket_id)
        + ")"
    )
