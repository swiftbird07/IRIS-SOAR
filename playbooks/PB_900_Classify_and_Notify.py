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
NOTIFY_RESOLVED_CASES = True  # If resolved cases should still be notified
import ipaddress
from typing import Union, List

import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, ContextProcess, AuditLog, Detection, ContextThreatIntel, DNSQuery, HTTP
from lib.config_helper import Config
from lib.generic_helper import cast_to_ipaddress, format_results, is_local_tld, handle_percentage

from integrations.matrix_notify import zs_notify
from integrations.znuny_otrs import zs_add_note_to_ticket, zs_get_ticket_by_number, zs_set_ticket_priority

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["matrix_notify"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["matrix_notify"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def get_emoji_for_threat_level(threat_level: str) -> str:
    """Gets the emoji for the threat level.

    Args:
        threat_level (str): The threat level

    Returns:
        str: The emoji for the threat level
    """
    if threat_level == "negligible":
        return ":white_circle:"
    elif threat_level == "low":
        return ":green_circle:"
    elif threat_level == "medium":
        return ":yellow_circle:"
    elif threat_level == "high":
        return ":orange_circle:"
    elif threat_level == "critical":
        return ":red_circle:"
    else:
        return ":question:"


def zs_can_handle_detection(case_file: CaseFile) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        case_file (CaseFile): The detection case

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    # Check if any of the detecions of the detection case is an Elastic Alert
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling anything.")
        return False

    # Check if there is already a ticket for the detection case
    try:
        ticket_number = case_file.get_ticket_number()
    except ValueError:
        mlog.info(f"Playbook '{PB_NAME}' cannot handle detection case '{case_file.uuid}' as there is no ticket for it.")
        return False
    return True


def zs_handle_detection(case_file: CaseFile, TEST=False) -> CaseFile:
    """Handles the detection.

    Args:
        case_file (CaseFile): The detection case
        TEST (bool): True if the playbook is run in test mode, False if not

    Returns:
        CaseFile: The updated detection case
    """
    # Get all the indicators
    cfg = Config().cfg
    integration_config = cfg["integrations"]["matrix_notify"]
    mlog.info(f"Handling detection case '{case_file.uuid}'")
    init_action = AuditLog(
        PB_NAME,
        0,
        "Getting detection case severity",
        "Started handling detection case by getting the highest severity of all detections and setting it as the appropriate threat level.",
    )
    case_file.update_audit(init_action, mlog)

    # Get the highest severity of all detections
    highest_severity = 0
    for detection in case_file.detections:
        if detection.severity > highest_severity:
            highest_severity = detection.severity
    case_file.update_audit(
        init_action.set_successful(message=f"Got the highest severity of all detections. Severity: {highest_severity}"), mlog
    )

    # Set the cases threat level according to the highest severity (One of "undetermined", "negligible", "low", "medium", "high", "critical")
    try:
        handle_percentage(highest_severity)  # throws an exception if the percentage is not between 0 and 100

        if highest_severity == 0:
            case_file.threat_level = "negligible"
        elif highest_severity <= 25:
            case_file.threat_level = "low"
        elif highest_severity <= 50:
            case_file.threat_level = "medium"
        elif highest_severity <= 75:
            case_file.threat_level = "high"
        elif highest_severity <= 100:
            case_file.threat_level = "critical"
    except Exception:
        mlog.error(f"Could not handle percentage '{highest_severity}'")
        case_file.update_audit(init_action.set_error(message=f"Could not handle percentage '{highest_severity}'"), mlog)

    # Set the priority of the ticket
    current_action = AuditLog(
        PB_NAME,
        1,
        "Setting ticket priority",
        "Setting the priority of the ticket based on the newly gathered threat level.",
    )
    case_file.update_audit(current_action, mlog)

    # Get the ticket
    ticket_number = case_file.get_ticket_number()
    ticket = zs_get_ticket_by_number(ticket_number)
    if ticket == None:
        mlog.error(f"Could not get ticket '{ticket_number}'")
        case_file.update_audit(current_action.set_error(message=f"Could not get ticket '{ticket_number}'"), mlog)
        return case_file

    # Set the priority according to the threat level
    if case_file.threat_level == "negligible":
        priority = "5 very low"
    elif case_file.threat_level == "low":
        priority = "4 low"
    elif case_file.threat_level == "medium":
        priority = "3 normal"
    elif case_file.threat_level == "high":
        priority = "2 high"
    elif case_file.threat_level == "critical":
        priority = "1 very high"
    else:
        mlog.error(f"Could not set priority of ticket '{ticket_number}' to a valid priority, as the threat level is invalid")
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not set priority of ticket '{ticket_number}' to a valid priority, as the threat level is invalid"
            ),
            mlog,
        )
        return case_file

    mlog.info(f"Setting priority of ticket '{ticket_number}' to '{priority}'")
    if TEST == False:
        if zs_set_ticket_priority(ticket_number, priority) == False:
            mlog.error(f"Could not set priority of ticket '{ticket_number}' to '{priority}'")
            case_file.update_audit(
                current_action.set_failed(f"Could not set priority of ticket '{ticket_number}' to '{priority}'"), mlog
            )
            return case_file
    case_file.update_audit(current_action.set_successful(f"Set priority of ticket '{ticket_number}' to '{priority}'"), mlog)

    # Close ticket if case status is "resolved"
    if case_file.status == "resolved":
        current_action = AuditLog(PB_NAME, 2, "Closing ticket", "Closing the ticket as the case is resolved.")
        case_file.update_audit(current_action, mlog)
        if TEST == False:
            if zs_set_ticket_state(ticket_number, "closed successful") == False:
                mlog.error(f"Could not close ticket '{ticket_number}'")
                case_file.update_audit(current_action.set_failed(f"Could not close ticket '{ticket_number}'"), mlog)
                return case_file
        case_file.update_audit(current_action.set_successful(f"Closed ticket '{ticket_number}'"), mlog)
    else:
        mlog.info(f"Case '{case_file.uuid}' is not resolved, so the ticket '{ticket_number}' will not be closed.")

    # Notify the user
    if case_file.status == "resolved" and not NOTIFY_RESOLVED_CASES:
        mlog.info(f"Case '{case_file.uuid}' is resolved, but notifications for resolved cases are disabled.")
        return case_file

    current_action = AuditLog(PB_NAME, 2, "Notifying user", "Notifying the user about the detection using Matrix.")
    case_file.update_audit(current_action, mlog)
    ticket_url = cfg["integrations"]["znuny_otrs"]["url"]
    ticket_url += TICKET_URL_PATH

    emoji = "ℹ️"  # default emoji (undetermined)
    if case_file.status == "resolved":
        emoji = "✅"
    elif case_file.status == "unresolved":
        emoji = "⚠️"

    # Firat format a message like this:
    #
    # #### ⚠️ New `UNRESOLVED` `ALERT` ticket was created in Znuny.
    #
    # #### Title
    #
    # `This is some Title | Offender: Someone`
    #
    # #### Threat Type
    #
    # `_Unknown_`
    #
    # #### Threat Level
    #
    # `Medium 🟡`
    #
    # #### Statistics:
    #
    #  ```
    # - Confidence: 45
    # - Playbooks handled: 2
    # - Number of Gathered Context Objects: 103
    # ```
    #
    # #### Action required?
    #
    #  - `Yes`
    number_of_gathered_context_objects = (
        len(case_file.context_processes)
        + len(case_file.context_files)
        + len(case_file.context_flows)
        + len(case_file.context_registries)
        + len(case_file.context_devices)
        + len(case_file.context_locations)
        + len(case_file.context_persons)
        + len(case_file.context_threat_intel)
    )

    message = f"#### {emoji} New `{case_file.status.upper()}` `{case_file.result.upper()}` ticket was created in Znuny.\n\n"
    message += f"#### Title\n\n`{case_file.title}`\n\n"
    message += f"#### Threat Type\n\n`{case_file.threat_type}`\n\n"
    message += (
        f"#### Threat Level\n\n`{case_file.threat_level.capitalize()} {get_emoji_for_threat_level(case_file.threat_level)}`\n\n"
    )
    message += f"#### Statistics:\n\n```\n- Confidence: {case_file.result_confidence}\n- Playbooks handled: {str(len(case_file.playbooks))}\n- Number of Gathered Context Objects: {str(number_of_gathered_context_objects)}\n```\n\n"
    message += f"#### Resolved?\n\n- `Yes`\n\n" if case_file.status == "resolved" else f"#### Resolved?\n\n- `No`\n\n"
    message += f"#### Ticket URL\n\n{ticket_url}\n\n"

    # Then send the message
    if TEST == False:
        if zs_notify(cfg["matrix_notify"], message, False):
            case_file.update_audit(current_action.set_successful("Notified user"), mlog)
        else:
            case_file.update_audit(current_action.set_failed("Failed to notify user."), mlog)
