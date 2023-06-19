# Playbook for Z-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by Z-SOAR
# It is used to generally handle Elastic SIEM (formerly known as Elastic Endpoint Security) detection alerts.
#
# Acceptable Detections:
#  - All elastic detections
#
# Gathered Context:
# - None
#
# Actions:
# - Create Ticket
# - Add notes to related tickets
#
PB_NAME = "PB_010_Generic_Elastic_Alerts"
PB_VERSION = "0.1.0"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True


from typing import Union, List
import json
import traceback

import lib.logging_helper as logging_helper
from lib.class_helper import DetectionReport, ContextProcess, AuditLog, Detection
from lib.config_helper import Config
from lib.generic_helper import format_results, get_unique, del_none_from_dict

from integrations.elastic_siem import zs_provide_context_for_detections
from integrations.znuny_otrs import zs_create_ticket, zs_add_note_to_ticket, zs_get_ticket_by_number

from playbooks.bb_elastic_context_fetcher import (
    bb_get_context_process_children,
    bb_get_context_process_parents,
    bb_get_context_process_network_flows,
    bb_get_context_process_file_events,
    bb_get_context_process_registry_events,
    bb_get_context_process_tree_visualisation,
)

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["elastic_siem"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["elastic_siem"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


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
    # Check if any of the detecions of the detection report is an Elastic Alert
    for detection in detection_report.detections:
        if detection.vendor_id == "elastic_siem":
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
    detection_id = detection_report.uuid
    current_action = AuditLog(
        PB_NAME,
        0,
        f"Checking Whitelist for detection '{detection_title}'",
        "Started handling detection report. Checking first if any detections are whitelisted.",
    )
    detection_report.update_audit(current_action, logger=mlog)

    detections_to_handle = []
    for detection in detection_report.detections:
        if detection.vendor_id == "elastic_siem":
            mlog.debug(f"Adding detection: '{detection.name}' ({detection.uuid}) to list.")
            detections_to_handle.append(detection)

    if len(detections_to_handle) == 0:
        mlog.critical("Found no detections in detection report to handle.")
        return detection_report

    detection: Detection = detections_to_handle[0]  # We only handle the first detection

    # First check the global whitelist for whitelist entries
    mlog.info(f"Checking global whitelist for detection: '{detection.name}' ({detection.uuid})")
    if detection.check_against_whitelist():
        mlog.info(f"Detection: '{detection.name}' ({detection.uuid}) is whitelisted, skipping.")
        detection_report.update_audit(current_action.set_successful(message="Detection is whitelisted, skipping."), logger=mlog)
        return detection_report
    detection_report.update_audit(current_action.set_successful(message="Detection is not whitelisted."), logger=mlog)

    # Create initial ticket for detection
    ticket_number = zs_create_ticket(
        detection_report, detection, False, auto_detection_note=True, playbook_name=PB_NAME, playbook_step=1
    )
    if not ticket_number:
        mlog.critical(f"Could not create ticket for detection: '{detection.name}' ({detection.uuid})")
        return detection_report

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

    # Gather process related contexts from BB_Elastic_Context_Fetcher:
    parents = []
    children = []
    process_tree = ""

    parents = bb_get_context_process_parents(PB_NAME, 2, mlog, detection_report, detection)
    children = bb_get_context_process_children(PB_NAME, 3, mlog, detection_report, detection)
    process_tree = bb_get_context_process_tree_visualisation(
        PB_NAME, 4, mlog, detection_report, detection, parents, children, current_action
    )

    process_names = []
    for process in detection_report.context_processes:
        process_names.append(f"{process.process_name} ({process.process_id})")

    # Create a note for Process Context
    zs_add_note_to_ticket(
        ticket_number,
        "context_process",
        False,
        playbook_name=PB_NAME,
        playbook_step=5,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=process_names,
        parents=parents,
        children=children,
        tree=process_tree,
    )

    # Gather Network related contexts from BB_Elastic_Context_Fetcher:
    detected_process_flows = []
    context_process_flows = []
    detected_process_flows, context_process_flows = bb_get_context_process_network_flows(
        PB_NAME, 6, mlog, detection_report, detection
    )

    # Create a note for Network Flows
    zs_add_note_to_ticket(
        ticket_number,
        "context_network",
        False,
        playbook_name=PB_NAME,
        playbook_step=8,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=detected_process_flows,
        other_contexts=context_process_flows,
    )

    # Gather File related contexts from BB_Elastic_Context_Fetcher:
    detected_process_file_events = []
    context_processes_file_events = []
    detected_process_file_events, context_processes_file_events, file_names = bb_get_context_process_file_events(
        PB_NAME, 8, mlog, detection_report, detection
    )

    # Create a note for File Events
    zs_add_note_to_ticket(
        ticket_number,
        "context_file",
        False,
        playbook_name=PB_NAME,
        playbook_step=10,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=detected_process_file_events,
        other_contexts=context_processes_file_events,
        file_names=file_names,
    )

    # Gather Registry related contexts from BB_Elastic_Context_Fetcher:
    detected_process_registry_events = []
    context_processes_registry_events = []
    detected_process_registry_events, context_processes_registry_events, _ = bb_get_context_process_registry_events(
        PB_NAME, 10, mlog, detection_report, detection
    )

    # Create a note for Registry Events
    zs_add_note_to_ticket(
        ticket_number,
        "context_registry",
        False,
        playbook_name=PB_NAME,
        playbook_step=12,
        detection_report=detection_report,
        detection=detection,
        detection_contexts=detected_process_registry_events,
        other_contexts=context_processes_registry_events,
    )

    return detection_report


# TODO:
# - Cache new detection and check if it similar events already in the cache
# - Empty cache if too big
# - Worker: Kill Playbook if stuck
# - Audit log respecting timeline order
# - Audit log to Ticket
# - Log / Audit Log to Syslog
