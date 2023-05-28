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
from lib.class_helper import DetectionReport, ContextProcess, ActionLog
from lib.config_helper import Config
from lib.generic_helper import format

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

def zs_handle_detection(detection_report: DetectionReport) -> DetectionReport:
    """Handles the detection.

    Args:
        detection_report (DetectionReport): The detection report

    Returns:
        DetectionReport: The detection report with the context processes
    """
    detection_title = detection_report.get_title()
    detection_id = detection_report.uuid
    mlog.info(f"Handling detection report: '{detection_title}' ({detection_id})")
    action = ActionLog(PB_NAME, 0, "Check Whitelist", "Started handling detection report. Checking if any detections are whitelisted.")
    detection_report.update_history(action)

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
        detection_report.update_history(action.set_successful(message="Detection is whitelisted, skipping."))
        return detection_report
    detection_report.update_history(action.set_successful(message="Detection is not whitelisted."))
    
    # Create ticket for detection
    mlog.info(f"Creating ticket for detection: '{detection.name}' ({detection.uuid})")
    action = ActionLog(PB_NAME, 1, "Create Ticket", "Creating ticket for detection.")
    detection_report.update_history(action)

    ticket_number = zs_create_ticket(detection_report)
    if ticket_number is None or not ticket_number:
        mlog.error(f"Failed to create ticket for detection: '{detection.name}' ({detection.uuid})")
        return detection_report
    
    # Add ticket to detection (-report)
    mlog.debug(f"Adding ticket to detection and detection report.")
    ticket = zs_get_ticket_by_number(ticket_number)
    detection.ticket = ticket
    detection_report.add_context(ticket)

    # Try to get the detection context
    mlog.info(f"Getting context for detection: '{detection.name}' ({detection.uuid})")
    parents = []
    try:
        parents = bb_get_all_parents(detection_report, detection.process)#
    except Exception as e:
        mlog.error(f"Failed to get parents for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
    if parents is None:
        mlog.warning(f"Got no parents for detection.")
    
    children = []
    try:
        children = bb_get_all_children(detection_report, detection.process)
    except Exception as e:
        mlog.error(f"Failed to get children for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
    if children is None:
        mlog.warning(f"Got no children for detection.")

    if parents is not None or children is not None:
        try:
            process_tree = bb_make_process_tree_visualisation(detection.process, parents, children)
        except Exception as e:
            mlog.error(f"Failed to create process tree visualisation for detection: '{detection.name}' ({detection.uuid}). Exception: {e}")
        if process_tree == "":
            mlog.warning(f"Failed to create process tree visualisation for detection.")

    # Create note for the parent/child processes
    try:
        mlog.info(f"Creating note for detection: '{detection.name}' ({detection.uuid})")
        body = f"Context regarding detected Process: {detection.process_name}\n"
        body += f"\n\nParent Processes:\n"
        body += "\n"+format(parents)
        body += f"\n\nChild Processes:\n"
        body += "\n"+format(children)

        if process_tree != "":
            body += f"\n\nProcess Tree:\n{process_tree}"
        body += "\n\nRelated Processes:\n"
        body += "\n"+format(detection_report.context_processes)

        note = zs_add_note_to_ticket(ticket_number, "raw", False, "Context: Processes", body, "text/html")
    except Exception as e:
        mlog.error(f"Failed to create note for processes in detection: '{detection.name}' ({detection.uuid}). Exception: {e}")



    
    
    

