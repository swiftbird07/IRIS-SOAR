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
from lib.class_helper import DetectionReport, ContextProcess, AuditLog
from lib.config_helper import Config
from lib.generic_helper import format_results

from integrations.elastic_siem import zs_provide_context_for_detections
from integrations.znuny_otrs import zs_create_ticket, zs_add_note_to_ticket, zs_get_ticket_by_number
from playbooks.bb_elastic_process_context import bb_get_all_children, bb_get_all_parents, bb_make_process_tree_visualisation

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
    
    detection = detections_to_handle[0] # We only handle the first detection

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

    ticket_number = zs_create_ticket(detection_report, DRY_RUN)
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

    # Try to get the detection context
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
        detection_report.update_audit(current_sub_action.set_successful(message=f"Found {len(parents)} parents for detection.", data=parents), logger=mlog)

    
    children = []
    current_sub_action = AuditLog(PB_NAME, 4, "Context - Get Children", "Gathering Children Process Context from Elastic.")
    try:
        children = bb_get_all_children(detection_report, detection.process)
    except Exception as e:
        mlog.error(f"Failed to get children for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_sub_action.set_error(message=f"Failed to get children for detection.", exception=e), logger=mlog)

    if children is None:
        mlog.warning(f"Got no children for detection.")
        detection_report.update_audit(current_sub_action.set_warning(warning_message=f"Found no children for detection."), logger=mlog)
    else:
        detection_report.update_audit(current_sub_action.set_successful(message=f"Found {len(parents)} children for detection.", data=children), logger=mlog)



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
    detection_report.update_audit(current_action.set_successful(message=f"Successfully gathered needed context for detection."), logger=mlog)

    # Create note for the parent/child processes
    try:
        current_action = AuditLog(PB_NAME, 6, "Create Note", "Creating note for processes in detection.")
        detection_report.update_audit(current_action, logger=mlog)
        # Replace "\n" by "<br" in process_tree
        process_tree = process_tree.replace("\n", "<br>")
        process_tree = process_tree.replace("    ", "&emsp;")

        body = f"<br><br>Process Tree:<br>{process_tree}"
        body += f"<br><br>Context regarding detected Process:<br><br>"
        body += f"Process Name: {detection.process.process_name}<br>"
        body += f"Process ID: {detection.process.process_id}<br>"
        body += f"Process Path: {detection.process.process_path}<br>"
        body += f"Process Command Line: {detection.process.process_command_line}<br>"
        body += f"Process SHA256: {detection.process.process_sha256}<br>"

        body += f"<br><br>Parent Processes:<br><br>"
        body += format_results(parents, "html", group_by="process_id")

        body += f"<br><br>Child Processes:<br>"
        body += "<br>"+format_results(children, "html", group_by="process_id")

        body += "<br><br>Other Related Processes:<br>"
        body += "<br>"+format_results(detection_report.context_processes, "html", group_by="process_id")

        note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, "Context: Processes", body, "text/html")
        if type(note_id) is not int:
            mlog.warning(f"Failed to create note for processes in detection.")
            detection_report.update_audit(current_action.set_error(warning_message=f"Failed to create note for processes in detection (returned).", exception=note_id), logger=mlog)
        else:
            mlog.info(f"Successfully created note for processes in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}")
            current_action.playbook_done = True
            detection_report.update_audit(current_action.set_successful(message=f"Successfully created note for processes in detection with note id: {note_id}", data=str(body), ticket_number=ticket_number), logger=mlog)
    except Exception as e:
        mlog.error(f"Failed to create note for processes in detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        detection_report.update_audit(current_action.set_error(message=f"Failed to create note for processes in detection (catched).", exception=e), logger=mlog)



    
    
    

