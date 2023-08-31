# Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally handle Suricata Alerts of IBM QRadar detections.
#
# Acceptable Detections:
#  - Detections from IBM QRadar that have a Suricata Alert
#
# Gathered Context:
# - ContextLog, ContextFlow
#
# Actions:
# - Add notes to related tickets
#
PB_NAME = "PB_020_Generic_Suricata_Alerts"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

from lib.class_helper import CaseFile, AuditLog, Detection, ContextLog, ContextFlow, ContextFile, Rule
from lib.logging_helper import Log
from lib.config_helper import Config
from integrations.znuny_otrs import zs_add_note_to_ticket, zs_update_ticket_title
from lib.generic_helper import format_results, dict_get

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_stdout"]
mlog = Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def zs_can_handle_detection(case_file: CaseFile) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        case_file (CaseFile): The detection case

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling detection.")
        return False

    for detection in case_file.detections:
        # Check if any of the detecions of the detection case is a QRadar Offense
        try:
            case_file.get_ticket_number()
        except ValueError:
            mlog.info(
                f"Playbook '{PB_NAME}' cannot handle detection '{detection.name}' ({detection.uuid}), as there is no ticket in it."
            )
            return False

        if detection.vendor_id == "IBM QRadar":
            for log in case_file.context_logs:
                if (
                    dict_get(log.log_custom_fields, "Alert - Signature") != None
                    and dict_get(log.log_custom_fields, "Alert - Action") != "store"
                ):
                    mlog.info(f"Playbook '{PB_NAME}' can handle detection '{detection.name}' ({detection.uuid}).")
                    return True
    mlog.info(f"Playbook '{PB_NAME}' cannot handle detection '{detection.name}' ({detection.uuid}).")
    return False


def zs_handle_detection(case_file: CaseFile, DRY_RUN=False) -> CaseFile:
    """Handles the detection.

    Args:
        case_file (CaseFile): The detection case
        DRY_RUN (bool, optional): If True, no external changes will be made. Defaults to False.

    Returns:
        CaseFile: The detection case with the context processes
    """
    detection_title = case_file.get_title()
    detections_to_handle = []
    for detection in case_file.detections:
        if detection.vendor_id == "IBM QRadar":
            mlog.debug(f"Adding detection: '{detection.name}' ({detection.uuid}) to list.")
            detections_to_handle.append(detection)

    if len(detections_to_handle) == 0:
        mlog.critical("Found no detections in detection case to handle.")
        return case_file

    detection: Detection = detections_to_handle[0]  # We primarily handle the first detection

    # Add rule information to detection
    current_action = AuditLog(
        PB_NAME,
        1,
        "Adding suricata rule information to detection.",
        "Adding new rules to the detection by parsing the Suricata Alert fields from the gathered ContextLogs",
    )
    case_file.update_audit(current_action, logger=mlog)

    rules_new = []

    # The following fields are parsed from the Suricata Alert:
    #           '"Alert - Created"',
    #            '"Alert - Action"',
    #            '"Alert - Category"',
    #            '"Alert - Domain"',
    #            '"Alert - SID"',
    #            '"Alert - Severity"',
    #            '"Alert - Signature"',
    #            '"Alert - Updated"',

    for log in case_file.context_logs:
        custom_fields = log.log_custom_fields
        if dict_get(custom_fields, "Alert - Signature") != None:
            rule = Rule(
                dict_get(custom_fields, "Alert - SID", "Unknown"),
                custom_fields["Alert - Signature"],
                custom_fields["Alert - Severity"],
                description="Category: " + custom_fields["Alert - Category"],
                tags=["Suricata", custom_fields["Alert - Category"]],
                raw=str(custom_fields),
                updated_at=dict_get(custom_fields, "Alert - Updated"),
            )
            rules_new.append(rule)
            # TODO: Add 'query' of Suricata rules from external source

    detection.rules.append(rules_new)
    case_file.update_audit(current_action.set_successful(message="Successfully added rules to detection."), logger=mlog)

    # Add note to related ticket
    current_action = AuditLog(PB_NAME, 2, "Adding note to related ticket.", "Adding note with new Rules to related ticket.")
    case_file.update_audit(current_action, logger=mlog)

    ticket_number = case_file.get_ticket_number()
    if ticket_number is None:
        mlog.critical("Could not find ticket number in detection case.")
        case_file.update_audit(current_action.set_error(message="Could not find ticket number in detection case."), logger=mlog)
        return case_file

    note_title = "Suricata Alert Rules"
    if len(rules_new) == 0:
        note_title += " (empty)"
        case_file.update_audit(
            current_action.set_warning(warning_message="No Suricata rules were found. Adding empty note."), logger=mlog
        )

    note_body = "<h2>Suricata Alert Rules</h2>"
    note_body += "<p>These are the Suricata Alert Rules that were parsed from the ContextLogs:</p>"
    note_body += "<br><br>"
    note_body += format_results(rules_new, "html", "")

    article_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, note_body, "text/html")
    if article_id is None:
        mlog.critical(f"Could not add note to ticket '{ticket_number}'.")
        case_file.update_audit(current_action.set_error(message=f"Could not add note to ticket '{ticket_number}'."), logger=mlog)
        return case_file
    case_file.update_audit(
        current_action.set_successful(message=f"Successfully added note to ticket '{ticket_number}'."), logger=mlog
    )

    # Update ticket title to include the Suricata Alert Signature
    current_action = AuditLog(
        PB_NAME, 3, "Updating ticket title.", "Updating ticket title to include the Suricata Alert Signature."
    )
    case_file.update_audit(current_action, logger=mlog)

    if len(rules_new) == 0:
        mlog.critical("Could not update ticket title, as there are no rules.")
        case_file.update_audit(
            current_action.set_error(message="Could not update ticket title, as there are no rules."), logger=mlog
        )
        return case_file

    title = "[IRIS-SOAR] Suricata Alert: "
    title_rule = rules_new[0].name
    title += title_rule

    # Search each rule for any other unique rule name that is not the first one
    new_rule_names = []
    for rule in rules_new:
        new_rule_names.append(rule.name)
    new_rule_names = list(set(new_rule_names))

    if len(new_rule_names) > 1:
        for rule_name in new_rule_names:
            if rule_name != title_rule:
                title += ", " + rule_name

    offender = []
    for log in case_file.context_logs:
        if log.log_source_device is not None:
            offender.append(log.log_source_device.name)

    if len(offender) == 0:
        offender.append(log.log_source_ip)
    if len(offender) == 1:
        title += " | Offender: " + str(offender[0])
    else:
        offender = list(set(offender))
        title += " | Offender: " + ", ".join(offender)

    mlog.info(f"Crafted new ticket title: '{title}'")

    ticket_number = zs_update_ticket_title(case_file, title)
    if ticket_number is None or type(ticket_number) == Exception:
        mlog.critical(f"Could not update ticket '{ticket_number}'.")
        case_file.update_audit(current_action.set_error(message=f"Could not update ticket '{ticket_number}'."), logger=mlog)
        return case_file
    case_file.update_audit(
        current_action.set_successful(message=f"Successfully updated ticket '{ticket_number}' title to '{title}'."), logger=mlog
    )

    # Update Detection severity
    current_action = AuditLog(
        PB_NAME, 4, "Updating detection severity.", "Updating detection severity based on Suricata Alert Severity."
    )
    case_file.update_audit(current_action, logger=mlog)
    max_severity = 0
    for rule in rules_new:
        if rule.severity and int(rule.severity) > max_severity:
            max_severity = int(rule.severity)

    if max_severity > 0:
        detection.severity = max_severity * 10
        case_file.detections[0] = detection
        case_file.update_audit(
            current_action.set_successful(message=f"Successfully updated detection severity to '{max_severity}'."), logger=mlog
        )
    else:
        case_file.update_audit(
            current_action.set_warning(warning_message="Could not find any severity > 0 to update."), logger=mlog
        )

    return case_file
