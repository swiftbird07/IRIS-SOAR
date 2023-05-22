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
PB_NAME = "010_Generic_Elastic_Alerts"
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
from lib.class_helper import DetectionReport, ContextProcess
from lib.config_helper import Config

from integrations.elastic_siem import zs_provide_context_for_detections
from integrations.znuny_otrs import zs_create_ticket
from playbooks.bb_elastic_process_context import bb_get_all_children, bb_get_all_parents

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

def zs_handle_detection(detection_report) -> DetectionReport:
    """Handles the detection.

    Args:
        detection_report (DetectionReport): The detection report

    Returns:
        DetectionReport: The detection report with the context processes
    """
    detection_title = detection_report.get_title()
    detection_id = detection_report.uuid
    mlog.info(f"Handling detection report: '{detection_title}' ({detection_id})")

    detections_to_handle = []
    for detection in detection_report.detections:
        if detection.vendor_id == "elastic_siem":
            mlog.debug(f"Adding detection: '{detection.title}' ({detection.uuid}) to list.")
            detections_to_handle.append(detection)

    if len(detections_to_handle) == 0:
        mlog.critical("Found no detections in detection report to handle.")
        return detection_report
    
    detection = detections_to_handle[0] # We only handle the first detection

    # First check the global whitelist for whitelist entries
    mlog.info(f"Checking global whitelist for detection: '{detection.title}' ({detection.uuid})")
    if detection.check_against_whitelist():
        mlog.info(f"Detection: '{detection.title}' ({detection.uuid}) is whitelisted, skipping.")
        return detection_report
    
    # Create ticket for detection
    mlog.info(f"Creating ticket for detection: '{detection.title}' ({detection.uuid})")
    ticket = zs_create_ticket(detection_report)
    if ticket is None or not ticket:
        mlog.error(f"Failed to create ticket for detection: '{detection.title}' ({detection.uuid})")
        return detection_report
    
    # Add ticket to detection (-report)
    mlog.debug(f"Adding ticket to detection and detection report.")
    detection.ticket = ticket
    detection_report.add_context(ticket)

    # Get the detection context
    mlog.info(f"Getting context for detection: '{detection.title}' ({detection.uuid})")
    parents = []
    parents = bb_get_all_parents(detection, detection.process)
    if parents is None:
        mlog.warning(f"Failed to get parents for detection.")
    
    children = []
    children = bb_get_all_children(detection, detection.process)
    if children is None:
        mlog.warning(f"Failed to get children for detection.")

    
    
    

