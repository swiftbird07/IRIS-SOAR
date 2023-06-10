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
#
PB_NAME = "PB_010_Generic_Elastic_Alerts"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

import sys
import os

import logging
from typing import Union, List
import datetime
import requests
from elasticsearch import Elasticsearch, AuthenticationException
from ssl import create_default_context
from functools import reduce
import sys
import uuid

import lib.logging_helper as logging_helper
from lib.class_helper import DetectionReport, ContextProcess, AuditLog, Detection
from lib.config_helper import Config
from lib.generic_helper import format_results, get_unique

from integrations.elastic_siem import zs_provide_context_for_detections
from integrations.znuny_otrs import zs_create_ticket, zs_add_note_to_ticket, zs_get_ticket_by_number
from playbooks.bb_elastic_process_context import bb_get_all_children, bb_get_all_parents, bb_make_process_tree_visualisation, bb_get_process_network_flows, bb_get_process_file_events

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
    # Check if any of the detecions of the detection report is an Elastic Alert
    for detection in detection_report.detections:
        if detection.vendor_id == "elastic_siem":
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
    current_action = AuditLog(PB_NAME, 0, f"Checking Whitelist for detection '{detection_title}'", "Started handling detection report. Checking first if any detections are whitelisted.")
    detection_report.update_audit(current_action, logger=mlog)

    detections_to_handle = []
    for detection in detection_report.detections:
        if detection.vendor_id == "elastic_siem":
            mlog.debug(f"Adding detection: '{detection.name}' ({detection.uuid}) to list.")
            detections_to_handle.append(detection)

    if len(detections_to_handle) == 0:
        mlog.critical("Found no detections in detection report to handle.")
        return detection_report
    
    detection: Detection = detections_to_handle[0] # We only handle the first detection

    # First check the global whitelist for whitelist entries
    mlog.info(f"Checking global whitelist for detection: '{detection.name}' ({detection.uuid})")
    if detection.check_against_whitelist():
        mlog.info(f"Detection: '{detection.name}' ({detection.uuid}) is whitelisted, skipping.")
        detection_report.update_audit(current_action.set_successful(message="Detection is whitelisted, skipping."), logger=mlog)
        return detection_report
    detection_report.update_audit(current_action.set_successful(message="Detection is not whitelisted."), logger=mlog)
    
    # Create ticket for detection
    current_action = AuditLog(PB_NAME, 1, "Create Ticket", "Creating ticket for detection.")
    detection_report.update_audit(current_action, logger=mlog)
    
    init_title = f"Detection: {detection.name} ({detection.uuid})"
    init_body = f"Detection: {detection.name} ({detection.uuid})\n\n"
    init_body += format_results(detection, "html", transform=True, group_by="")

    ticket_number = zs_create_ticket(detection_report, DRY_RUN,init_note_title=init_title, init_note_body=init_body)
    if ticket_number is None or not ticket_number:
        mlog.error(f"Failed to create ticket for detection: '{detection.name}' ({detection.uuid})")
        detection_report.update_audit(current_action.set_error(message="Failed to create ticket for detection (No ticket_number returned)."), logger=mlog)
        return detection_report
    else:
        mlog.info(f"Successfully created ticket for detection: '{detection.name}' ({detection.uuid}) with ticket number: {ticket_number}")
        detection_report.update_audit(current_action.set_successful(message=f"Successfully created ticket for detection with ticket number: {ticket_number}", ticket_number=ticket_number), logger=mlog)
    
    # Add ticket to detection (-report)
    mlog.debug(f"Adding ticket to detection and detection report.")
    if not DRY_RUN:
        ticket = zs_get_ticket_by_number(ticket_number)
        detection.ticket = ticket
        detection_report.add_context(ticket)

    # Try to get the detected process's parents
    current_action = AuditLog(PB_NAME, 2, "Gathering Context", "Gathering Context for detection.")
    detection_report.update_audit(current_action, logger=mlog)

    current_sub_action = AuditLog(PB_NAME, 3, "Context - Get Parents", "Gathering Parent Process Context from Elastic.")
    detection_report.update_audit(current_sub_action, logger=mlog)
    parents = []
    try:
        parents = bb_get_all_parents(detection_report, detection.process)#
    except Exception as e:
        mlog.error(f"Failed to get parents for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_sub_action.set_error(message=f"Failed to get parents for detection.", exception=e), logger=mlog)

    if parents is None:
        mlog.warning(f"Got no parents for detection.")
        detection_report.update_audit(current_sub_action.set_warning(warning_message=f"Found no parents for detection."), logger=mlog)
    else:
        process_names = []
        for process in detection_report.context_processes:
            process_names.append(f"{process.process_name} ({process.process_id})")
        detection_report.update_audit(current_sub_action.set_successful(message=f"Found {len(parents)} parents for detection.", data=process_names), logger=mlog)

    # Try to get the detected process's children
    children = []
    thrown_count = 0
    current_sub_action = AuditLog(PB_NAME, 4, "Context - Get Children", "Gathering Children Process Context from Elastic.")
    try:
        children, thrown_count = bb_get_all_children(detection_report, detection.process)
    except Exception as e:
        mlog.error(f"Failed to get children for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_sub_action.set_error(message=f"Failed to get children for detection.", exception=e), logger=mlog)

    if children is None:
        mlog.warning(f"Got no children for detection.")
        detection_report.update_audit(current_sub_action.set_warning(warning_message=f"Found no children for detection."), logger=mlog)
    else:
        if thrown_count > 0:
            mlog.warning(f"[OVERFLOW PROTECTION] Got {len(children)} children for detection, but {thrown_count} children were thrown due to overflow protection.")
            detection_report.update_audit(current_sub_action.set_warning(warning_message=f"[OVERFLOW PROTECTION] Found {len(children)} children for detection, but {thrown_count} children were thrown due to overflow protection."), logger=mlog)
        
        process_names = []
        for process in detection_report.context_processes:
            process_names.append(f"{process.process_name}")
        detection_report.update_audit(current_sub_action.set_successful(message=f"Found {len(parents)} children for detection.", data=process_names), logger=mlog)


    # Create process tree visualisation if parents or children is not None
    if parents is not None or children is not None:
        current_sub_action = AuditLog(PB_NAME, 5, "Context - Process Tree", "Gathering Process Tree from BB.")
        try:
            process_tree = bb_make_process_tree_visualisation(detection.process, parents, children)
        except Exception as e:
            mlog.error(f"Failed to create process tree visualisation for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
            detection_report.update_audit(current_sub_action.set_error(message=f"Failed to create process tree visualisation for detection.", exception=e), logger=mlog)
        if process_tree == "":
            mlog.warning(f"Failed to get process tree visualisation for detection.")
            detection_report.update_audit(current_sub_action.set_warning(warning_message=f"Failed to get process tree visualisation for detection (empty response)."), logger=mlog)
        else:
            detection_report.update_audit(current_sub_action.set_successful(message=f"Successfully created process tree visualisation for detection.", data=process_tree), logger=mlog)
    else:
        detection_report.update_audit(current_action.set_warning(warning_message=f"Found no context processes for detection."), logger=mlog)


    # Create a note for Process Context
    try:
        current_action = AuditLog(PB_NAME, 6, "Create Note - Process Context", "Creating note for processes in detection.")
        detection_report.update_audit(current_action, logger=mlog)
        # Replace "\n" by "<br" in process_tree
        process_tree = process_tree.replace("\n", "<br>")
        process_tree = process_tree.replace("    ", "&emsp;")

        body = f"<br><br><h2>Process Context:</h2><br><br>"
        body += f"<br><br><h3>Process Tree:</h3><br>{process_tree}"
        body += f"<br><br><h3>Context regarding detected Process:</h3><br><br>"
        body += f"Process Name: {detection.process.process_name}<br>"
        body += f"Process ID: {detection.process.process_id}<br>"
        body += f"Process Path: {detection.process.process_path}<br>"
        body += f"Process Command Line: {detection.process.process_command_line}<br>"
        body += f"Process SHA256: {detection.process.process_sha256}<br>"

        body += f"<br><br><h3>List of all reported process names: </h3><br><br>"
        body += f"{get_unique(process_names)}"

        body += f"<br><br><h3>Parent Processes:<br><br><h3>"
        body += format_results(parents, "html", group_by="process_id")

        body += f"<br><br><h3>Child Processes:</h3><br>"
        body += "<br>"+format_results(children, "html", group_by="process_id")

        body += "<br><br><h3>Complete Process Timeline:</h3><br>"
        body += "<br>"+format_results(detection_report.context_processes, "html", group_by="timestamp")

        note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, "Context: Processes", body, "text/html")
        if type(note_id) is not int:
            mlog.warning(f"Failed to create note for processes in detection.")
            detection_report.update_audit(current_action.set_error(warning_message=f"Failed to create note for processes in detection (returned).", exception=note_id), logger=mlog)
        else:
            mlog.info(f"Successfully created note for processes in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}")
            detection_report.update_audit(current_action.set_successful(message=f"Successfully created note for processes in detection with note id: {note_id}", ticket_number=ticket_number), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to create note for processes in detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to create note for processes in detection (catched).", exception=e), logger=mlog)

    # Gather network flows from alerted process
    try:
        current_action = AuditLog(PB_NAME, 7, "Context - Network Flows (Detected Process)", "Gathering network flows of detected process from BB.")
        detection_report.update_audit(current_action, logger=mlog)
        detected_process_flows, thrown_count = bb_get_process_network_flows(detection_report, detection.process)
        if detected_process_flows is None:
            mlog.warning(f"Got no network flows for detection.")
            detection_report.update_audit(current_action.set_warning(warning_message=f"Found no network flows for detected process."), logger=mlog)
        else:
            destination_ips = []
            for flow in detection_report.context_flows: # Add all destination IPs from context flows to list for the audit log
                destination_ips.append(flow.destination_ip)

            detection_report.update_audit(current_action.set_successful(message=f"Found {len(detected_process_flows)} network flows for detected process.", data=destination_ips), logger=mlog)
            
            if thrown_count > 0:
                mlog.warning(f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows for detected process.")
                detection_report.update_audit(current_action.set_warning(warning_message=f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows out for detected process, due to overflow protection."), logger=mlog)

    except Exception as e:
        mlog.error(f"Failed to get network flows for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to get network flows for detection.", exception=e), logger=mlog)

    # Gather network flows from (other) context processes
    try:
        current_action = AuditLog(PB_NAME, 8, "Context - Network Flows (Other Processes)", "Gathering network flows of other processes from BB.")
        detection_report.update_audit(current_action, logger=mlog)
        context_processes_flows = []
        thrown_count = 0

        for process in detection_report.context_processes:
            new_flow, thrown_count = bb_get_process_network_flows(detection_report, process)
            if new_flow is not None:
                
                if thrown_count > 0:
                    mlog.warning(f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows out for process: {process.process_name} ({process.process_id}).")
                    detection_report.update_audit(current_action.set_warning(warning_message=f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows out for process: {process.process_name} ({process.process_id}), due to overflow protection."), logger=mlog)
                
                context_processes_flows += new_flow
        if len(context_processes_flows) == 0:
            mlog.warning(f"Got no network flows from other processes.")
            detection_report.update_audit(current_action.set_warning(warning_message=f"Found no network flows for other context processes."), logger=mlog)
        else:
            destination_ips = []
            for flow in detection_report.context_flows: # Add all destination IPs from context flows to list for the audit log
                destination_ips.append(flow.destination_ip)

            detection_report.update_audit(current_action.set_successful(message=f"Found {len(context_processes_flows)} network flows for other processes of detection.", data=destination_ips), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to get network flows for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to get network flows for detection.", exception=e), logger=mlog)

    detection_report.update_audit(current_action.set_successful(message=f"Successfully gathered needed context for detection."), logger=mlog)

    # Create a note for Network Context
    try:
        current_action = AuditLog(PB_NAME, 9, "Create Note - Network Context", "Creating note for network flows in the detection.")
        detection_report.update_audit(current_action, logger=mlog)
        note_title = "Context: Network Flows"

        # Check if any network flows were found
        if detected_process_flows is None and len(context_processes_flows) == 0 and len(detection_report.context_flows) == 0:
            detection_report.update_audit(current_action.set_warning(warning_message=f"Found no network flows for detection."), logger=mlog)
            note_title += " (empty)"

        body = f"<br><br><h2>Network Context:</h2><br><br>"
        body += f"<h3>Network Flows of detected Process '{detection.process.process_name}' ({detection.process.process_id}):</h3><br><br>"
        body += format_results(detected_process_flows, "html", group_by="timestamp")

        body += f"<br><br><h3>List of all reported IPs and domains: </h3><br><br>"
        body += str(detection_report.indicators["ip"])+"<br>"+str(detection_report.indicators["domain"])+ "<br><br>"
        body += f"<br><br><h3>Network Flows of other Processes (grouped by process):</h3><br><br>"
        body += format_results(context_processes_flows, "html", group_by="process_id")

        body += "<br><br><h3>Complete Network Timeline:</h3><br>"
        body += "<br>"+format_results(detection_report.context_flows, "html", group_by="timestamp")

        note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, body, "text/html")
        if type(note_id) is not int:
            mlog.warning(f"Failed to create note for network in detection.")
            detection_report.update_audit(current_action.set_error(warning_message=f"Failed to create note for network in detection (returned).", exception=note_id), logger=mlog)
        else:
            mlog.info(f"Successfully created note for network in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}")
            current_action.playbook_done = True
            detection_report.update_audit(current_action.set_successful(message=f"Successfully created note for network in detection with note id: {note_id}", ticket_number=ticket_number), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to create note for network in detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to create note for network in detection (catched).", exception=e), logger=mlog)


    # Gather file events from alerted process
    try:
        current_action = AuditLog(PB_NAME, 10, "File Events - Alerted Process", "Gathering file events of alerted process from BB.")
        detection_report.update_audit(current_action, logger=mlog)
        detected_process_file_events = bb_get_process_file_events(detection_report, detection.process)
        if detected_process_file_events is None:
            mlog.warning(f"Got no file events for detection.")
            detection_report.update_audit(current_action.set_warning(warning_message=f"Found no file events for detected process."), logger=mlog)
        else:
            file_names = []
            for event in detected_process_file_events[0]: # Gather all file names for the audit log
                file_names.append(event.file_name)
            detection_report.update_audit(current_action.set_successful(message=f"Found {len(detected_process_file_events)} file events for detected process.", data=file_names), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to get file events for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to get file events for detection.", exception=e), logger=mlog)

    # Gather file events from other context processes
    try:
        current_action = AuditLog(PB_NAME, 11, "File Events - Other Processes", "Gathering file events of other processes from BB.")
        detection_report.update_audit(current_action, logger=mlog)
        context_processes_file_events = []
        thrown_count = 0

        for process in detection_report.context_processes:
            new_events, thrown_count = bb_get_process_file_events(detection_report, process)
            if new_events is not None:
                
                if thrown_count > 0:
                    mlog.warning(f"[OVERFLOW PROTECTION] Threw {thrown_count} file events out for process: {process.process_name} ({process.process_id}).")
                    detection_report.update_audit(current_action.set_warning(warning_message=f"[OVERFLOW PROTECTION] Threw {thrown_count} file events out for process: {process.process_name} ({process.process_id}), due to overflow protection."), logger=mlog)
                
                context_processes_file_events += new_events
        if len(context_processes_file_events) == 0:
            mlog.warning(f"Got no file events from other processes.")
            detection_report.update_audit(current_action.set_warning(warning_message=f"Found no file events for other context processes."), logger=mlog)
        else:
            file_names = []
            for event in context_processes_file_events: # Gather all file names for the audit log
                file_names.append(event.file_name)
            detection_report.update_audit(current_action.set_successful(message=f"Found {len(context_processes_file_events)} file events for other processes of detection.", data=file_names), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to get file events for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to get file events for detection.", exception=e), logger=mlog)

    # Create a note for File Events
    try:
        current_action = AuditLog(PB_NAME, 12, "Create Note - File Events", "Creating note for file events in the detection.")
        detection_report.update_audit(current_action, logger=mlog)
        note_title = "Context: File Events"

        # Check if any file events were found
        if detected_process_file_events is None and len(context_processes_file_events) == 0 and len(detection_report.context_file_events) == 0:
            detection_report.update_audit(current_action.set_warning(warning_message=f"Found no file events for detection."), logger=mlog)
            note_title += " (empty)"

        body = f"<br><br><h2>File Event Context:</h2><br><br>"
        body += f"<h3>File Events of detected Process '{detection.process.process_name}' ({detection.process.process_id}):</h3><br><br>"
        body += format_results(detected_process_file_events[0], "html", group_by="timestamp")

        body += f"<br><br><h3>List of all reported files: </h3><br><br>"
        body += f"{get_unique(file_names)}"
        body += f"<br><br><h3>File Events of other Processes (grouped by process):</h3><br><br>"
        body += format_results(context_processes_file_events, "html", group_by="process_id")

        body += "<br><br><h3>Complete File Event Timeline:</h3><br>"
        body += "<br>"+format_results(detection_report.context_files, "html", group_by="timestamp")

        note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, body, "text/html")
        if type(note_id) is not int:
            mlog.warning(f"Failed to create note for file events in detection.")
            detection_report.update_audit(current_action.set_error(warning_message=f"Failed to create note for file events in detection (returned).", exception=note_id), logger=mlog)
        else:
            mlog.info(f"Successfully created note for file events in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}")
            current_action.playbook_done = True
            detection_report.update_audit(current_action.set_successful(message=f"Successfully created note for file events in detection with note id: {note_id}", ticket_number=ticket_number), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to create note for file events in detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to create note for file events in detection (catched).", exception=e), logger=mlog)
# TODO:
# - File context
# - Registry context
# - Threat Intel context
# - Host / Server context
# - Historical context
# - Analysis (manual / automated)