# Playbook for Z-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by Z-SOAR
# It is used to generally handle IBM QRadar Offenses and add context to them.
#
# Acceptable Detections:
#  - All elastic detections
#
# Gathered Context:
# - ContextLog, ContextFlow, ContextFile
#
# Actions:
# - Create Ticket
# - Add notes to related tickets
#
PB_NAME = "PB_011_Generic_QRadar_Offenses"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

from lib.class_helper import DetectionReport, AuditLog, Detection, ContextLog, ContextFlow, ContextFile
from lib.logging_helper import Log
from lib.config_helper import Config
from integrations.znuny_otrs import zs_create_ticket, zs_add_note_to_ticket, zs_get_ticket_by_number
from integrations.ibm_qradar import zs_provide_context_for_detections

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_stdout"]
mlog = Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def zs_can_handle_detection(detection_report: DetectionReport) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        detection_report (DetectionReport): The detection report

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling detection.")
        return False
    # Check if any of the detecions of the detection report is a QRadar Offense
    for detection in detection_report.detections:
        if detection.vendor_id == "IBM QRadar":
            mlog.info(f"Playbook '{PB_NAME}' can handle detection '{detection.name}' ({detection.uuid}).")
            return True
    return False


def zs_handle_detection(detection_report: DetectionReport, DRY_RUN=False) -> DetectionReport:
    """Handles the detection.

    Args:
        detection_report (DetectionReport): The detection report
        DRY_RUN (bool, optional): If True, no external changes will be made. Defaults to False.

    Returns:
        DetectionReport: The detection report with the context processes
    """
    detection_title = detection_report.get_title()
    detections_to_handle = []
    for detection in detection_report.detections:
        if detection.vendor_id == "IBM QRadar":
            mlog.debug(f"Adding detection: '{detection.name}' ({detection.uuid}) to list.")
            detections_to_handle.append(detection)

    if len(detections_to_handle) == 0:
        mlog.critical("Found no detections in detection report to handle.")
        return detection_report

    detection: Detection = detections_to_handle[0]  # We primarily handle the first detection

    # First check the global whitelist for whitelist entries
    current_action = AuditLog(
        PB_NAME,
        0,
        f"Checking Whitelist for detection '{detection_title}'",
        "Started handling detection report. Checking first if any detections are whitelisted.",
    )
    detection_report.update_audit(current_action, logger=mlog)
    mlog.info(f"Checking global whitelist for detection: '{detection.name}' ({detection.uuid})")
    if detection.check_against_whitelist():
        detection_report.update_audit(current_action.set_successful(message="Detection is whitelisted, skipping."), logger=mlog)
        return detection_report
    detection_report.update_audit(current_action.set_successful(message="Detection is not whitelisted."), logger=mlog)

    current_action = AuditLog(PB_NAME, 1, f"Creating ticket", f"Creating ticket for detection '{detection_title}'")
    # Create initial ticket for detection
    ticket_number = zs_create_ticket(
        detection_report, detection, False, auto_detection_note=True, playbook_name=PB_NAME, playbook_step=1
    )
    if not ticket_number:
        mlog.critical(f"Could not create ticket for detection: '{detection.name}' ({detection.uuid})")
        detection_report.update_audit(current_action.set_error(message=f"Could not create ticket."), logger=mlog)
        return detection_report
    detection_report.update_audit(current_action.set_successful(message=f"Created ticket '{ticket_number}'."), logger=mlog)

    # Create additional notes for each other detection in the detection report
    if len(detection_report.detections) > 1:
        sub_step = 1
        for other_detection in detection_report.detections:
            if other_detection.uuid != detection.uuid:
                zs_add_note_to_ticket(
                    ticket_number,
                    detection_report,
                    other_detection,
                    False,
                    auto_detection_note=True,
                    playbook_name=PB_NAME,
                    playbook_step=100 + sub_step,
                )
                sub_step += 1

    # Add ticket to detection (-report)
    mlog.debug(f"Adding ticket to detection and detection report.")
    if not DRY_RUN:
        ticket = zs_get_ticket_by_number(ticket_number)
        detection.ticket = ticket
        detection_report.add_context(ticket)

    # Gather offense related context
    current_action = AuditLog(
        PB_NAME,
        3,
        f"Gathering further context for offense '{detection_title}'",
        "Started gathering context of events that were in the original offense.",
    )
    detection_report.update_audit(current_action, logger=mlog)
    flows = []
    flows = zs_provide_context_for_detections(detection_report, ContextFlow, search_type="offense", search_value=detection.uuid)
    if type(flows) is Exception:
        detection_report.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{detection_title}'. Error: {flows}", data=flows
            ),
            logger=mlog,
        )
        flows = []
    elif flows:
        for flow in flows:
            detection_report.add_context(flow)

    logs = []
    logs = zs_provide_context_for_detections(detection_report, ContextLog, search_type="offense", search_value=detection.uuid)
    if type(logs) is Exception:
        detection_report.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{detection_title}'. Error: {logs}", data=logs
            ),
            logger=mlog,
        )
        logs = []
    elif logs:
        for log in logs:
            detection_report.add_context(log)

    files = []
    files = zs_provide_context_for_detections(detection_report, ContextFile, search_type="offense", search_value=detection.uuid)
    if type(files) is Exception:
        detection_report.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{detection_title}'. Error: {files}", data=files
            ),
            logger=mlog,
        )
        files = []
    elif files:
        for file in files:
            detection_report.add_context(file)

    if len(flows) > 0 or len(logs) > 0 or len(files) > 0:
        detection_report.update_audit(
            current_action.set_successful(
                message=f"Found {len(flows)} flows, {len(logs)} logs and {len(files)} files that were in the original offense."
            ),
            logger=mlog,
        )
    else:
        detection_report.update_audit(
            current_action.set_warning(warning_message=f"Found no flows, logs or files that were in the original offense."),
            logger=mlog,
        )

    current_action = AuditLog(PB_NAME, 4, f"Adding context to ticket '{ticket_number}'", "Started adding context to ticket.")

    # Create a note for each context
    note_id_1 = zs_add_note_to_ticket(
        ticket_number,
        "context_network",
        False,
        playbook_name=PB_NAME,
        playbook_step=4,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=flows,
    )
    note_id_2 = zs_add_note_to_ticket(
        ticket_number,
        "context_log",
        False,
        playbook_name=PB_NAME,
        playbook_step=5,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=logs,
    )
    note_id_3 = zs_add_note_to_ticket(
        ticket_number,
        "context_file",
        False,
        playbook_name=PB_NAME,
        playbook_step=6,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=files,
    )

    if not note_id_1 or type(note_id_1) is Exception:
        detection_report.update_audit(
            current_action.set_error(message=f"Could not add context network to ticket '{ticket_number}'. Error: {note_id_1}"),
            logger=mlog,
        )

    if not note_id_2 or type(note_id_2) is Exception:
        detection_report.update_audit(
            current_action.set_error(message=f"Could not add context log to ticket '{ticket_number}'. Error: {note_id_2}"),
            logger=mlog,
        )

    if not note_id_3 or type(note_id_3) is Exception:
        detection_report.update_audit(
            current_action.set_error(message=f"Could not add context file to ticket '{ticket_number}'. Error: {note_id_3}"),
            logger=mlog,
        )

    if (
        note_id_1
        and note_id_2
        and note_id_3
        and type(note_id_1) is not Exception
        and type(note_id_2) is not Exception
        and type(note_id_3) is not Exception
    ):
        detection_report.update_audit(
            current_action.set_successful(message=f"Successfully added all offense contexts to ticket '{ticket_number}'."),
            logger=mlog,
        )

    # Add ticket to detection (-report)
    mlog.debug(f"Adding ticket to detection and detection report.")
    ticket = zs_get_ticket_by_number(ticket_number)
    detection.ticket = ticket
    detection_report.add_context(ticket)

    return detection_report
