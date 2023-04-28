# Building Block for Z-SOAR Playbooks
# Created by: Martin Offermann
#
# This is a building book used by Z-SOAR Playbooks
# It is used to provide basic context to ContextProcess detection alerts of Elastic SIEM (formerly known as Elastic Endpoint Security).
#
# Acceptable Detections:
#  - All elastic detections related to process activity
#
# Gathered Context:
# - ContextProcess tree
#
# Actions:
# - None
#

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
from integrations.elastic_siem import zs_provide_context_for_detections
from lib.config_helper import Config

BB_NAME = "BB_Elastic_Process_Context"
BB_VERSION = "1.0.0"
BB_AUTHOR = "Martin Offermann"
BB_LICENSE = "MIT"
BB_ENABLED = True

# Prepare the logger
mlog = logging_helper.Log("playbooks." + BB_NAME)
process_cache = {}


def bb_get_complete_process_by_uuid(detection_report: DetectionReport, uuid) -> ContextProcess:
    """
    Returns a complete process object from Elastic SIEM by UUID.

    :param detection_report: A DetectionReport object
    :param uuid: The UUID of the process to enrich
    :return: A ContextProcess object
    """

    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]
    mlog.debug("complete_process_by_uuid - Fetching complete process for UUID: " + str(uuid))

    # Gather context
    processes = zs_provide_context_for_detections(integration_config, detection_report, ContextProcess, UUID=uuid, maxContext=1, TEST=False)
    if processes == None:
        mlog.debug("complete_process_by_uuid - No process found for UUID: " + str(uuid))
        return None
    
    # Sanity check
    if len(processes) > 1:
        mlog.warning("complete_process_by_uuid - More than one process found for UUID: " + str(uuid))
    
    process = processes[0]
    mlog.debug("complete_process_by_uuid - Returning process: " + str(process))
    return process


def get_all_children_recursive(detection_report, children: List, process: ContextProcess):
    for child in process.process_children:
        if len(child) == 0:
            child_full = bb_get_complete_process_by_uuid(detection_report, process.process_uuid)
            children.append(child_full)
        else:
            children.extend(bb_get_all_children(children, child))
    return children


def bb_get_all_children(detection_report: DetectionReport, process: ContextProcess) -> List[ContextProcess]:
    """Returns all children (meaning all leafs) of a process

    :param detection_report: A DetectionReport object
    :param process: The process to get the children for

    :return: A list of ContextProcess objects
    """
    children = []
    all_children = get_all_children_recursive(detection_report, children, process)

    for child in all_children:
        detection_report.add_context(child)

    # Sort the list by start time
    all_children.sort(key=lambda x: x.process_start_time, reverse=False)

    return all_children


def get_all_parents_recursive(detection_report, parents: List, process: ContextProcess):
    mlog.debug("get_all_parents_recursive - Getting all parents for process UUID: " + str(process.process_uuid) + " and name: " + str(process.process_name))
    mlog.debug(" Current parents: " + str(parents))

    parent_uuid = process.process_parent
    if parent_uuid == "" or parent_uuid == None:
        mlog.debug("get_all_parents_recursive - No parent found process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid))
        #process = bb_get_complete_process_by_uuid(detection_report, process.process_uuid)
        #parents.append(process)
    else:
        mlog.debug("get_all_parents_recursive - Parent found for process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid) + ". Parent UUID: " + str(parent_uuid))
        parent = bb_get_complete_process_by_uuid(detection_report, parent_uuid)
        if parent == None:
            mlog.warning("get_all_parents_recursive - Parent not found for UUID: " + str(parent_uuid))
            return parents
        mlog.debug("get_all_parents_recursive - ...Parent name: " + str(parent.process_name))
        parents.append(parent)
        get_all_parents_recursive(detection_report, parents, parent)
    return parents


def bb_get_all_parents(detection_report: DetectionReport, process: ContextProcess) -> List[ContextProcess]:
    """Returns all parents (meaning all root nodes, without all their childs) of a process

    :param detection_report: A DetectionReport object
    :param process: The process to get the parents for

    :return: A list of ContextProcess objects
    """
    mlog.debug("get_all_parents - Getting all parents for process: " + str(process))

    parents = []
    all_parents = get_all_parents_recursive(detection_report, parents, process)

    for parent in all_parents:
        detection_report.add_context(parent)

    # Sort the list by start time from newest to oldest
    parents.sort(key=lambda x: x.process_start_time, reverse=True)

    return parents

# TODO: Test Parent and Child functions