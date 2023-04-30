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
cfg = Config().cfg
log_level_file = cfg["integrations"]["elastic_siem"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["elastic_siem"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + BB_NAME, log_level_file, log_level_stdout)


def bb_get_all_processes_by_uuid(detection_report: DetectionReport, uuid, children=False) -> ContextProcess:
    """
    Returns a complete process object from Elastic SIEM by UUID.

    :param detection_report: A DetectionReport object
    :param uuid: The UUID of the process to enrich
    :param children: If True, the function will return all children of the process
    :return: A ContextProcess object
    """

    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]
    mlog.debug("bb_get_all_processes_by_uuid - Fetching complete process for UUID: " + str(uuid))

    # Gather context
    processes = zs_provide_context_for_detections(integration_config, detection_report, ContextProcess, UUID=uuid, maxContext=-1, TEST=False, UUID_is_parent=children)
    if processes == None:
        if children == False:
            mlog.debug("bb_get_all_processes_by_uuid - No process found for UUID: " + str(uuid))
        else:
            mlog.debug("bb_get_all_processes_by_uuid - No children found for process UUID: " + str(uuid))
        return None
    
    # Sanity check
    if len(processes) > 1 and children == False:
        mlog.warning("bb_get_all_processes_by_uuid - More than one process found for single process search. UUID of searched process: " + str(uuid))
        mlog.warning("bb_get_all_processes_by_uuid - Returning first process found: " + str(processes[0]))
    
    if not children:
        process = processes[0]
        mlog.debug("bb_get_all_processes_by_uuid - Returning process: " + str(process.process_name))
        return process
    else:
        mlog.debug("bb_get_all_processes_by_uuid - Returning list of found child processes of length: " + str(len(processes)))
        return processes

def get_all_children_recursive(detection_report, children: List, process: ContextProcess, done_hashes: List = [], all_process_events = False):
    """
    Returns all children of a process recursively.

    :param detection_report: A DetectionReport object
    :param children: A list of children already found (should be empty when first calling the function)
    :param process: The current process to get the children for
    :param uuids: A list of UUIDs of processes that have already been processed
    :param all_process_events: If True, the function will return all events for the process. If False, only the first found event for every unique process will be returned. Default: False
    """
    mlog.debug("get_all_children_recursive - Getting all children for process UUID: " + str(process.process_uuid) + " and name: " + str(process.process_name))
    mlog.debug(" Current children in List: " + str(children))

    # Get all children for the current process by searching for all processes with the current process as parent
    new_children = bb_get_all_processes_by_uuid(detection_report, process.process_uuid, children=True)

    if new_children == [] or new_children == None:
        mlog.debug("get_all_children_recursive - No children found for process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid))
        return children
    if type(new_children) != list and type(new_children) == ContextProcess:
        mlog.debug("get_all_children_recursive - Only one child found for process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid))
        new_children = [new_children]


    for child in new_children:
        if child.process_uuid == process.process_uuid:
            mlog.error("get_all_children_recursive - ! Stopped possible endless loop: Child UUID is the same as current process UUID ! Skipping this child.")
            continue

        if child == "" or child == None or type(child) != ContextProcess:
            mlog.debug("get_all_children_recursive - skipping found 'child' because it is empty or not a ContextProcess object: " + str(child))
            continue
        else:
            mlog.debug("get_all_children_recursive - child found for process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid) + ". child UUID: " + str(child) + ". Adding it to current process as child and DetectionReport context...")
            process.process_children.append(child)
            detection_report.add_context(child)
            if  not all_process_events and (child.process_sha256 in done_hashes):
                mlog.error("get_all_children_recursive - Skipping adding child to return list because a process with the same hash is already in it. Child SHA256: " + str(child.process_sha256))
                continue
            mlog.debug("get_all_children_recursive - will append " + str(child.process_name) +" to return list and fetch children for this child now...")
            children.append(child)
            done_hashes.append(child.process_sha256)
            get_all_children_recursive(detection_report, children, child)
    return children, done_hashes


def bb_get_all_children(detection_report: DetectionReport, process: ContextProcess) -> List[ContextProcess]:
    """Returns all children (meaning all leafs) of a process

    :param detection_report: A DetectionReport object
    :param process: The process to get the children for

    :return: A list of ContextProcess objects
    """
    children = []
    all_children, _ = get_all_children_recursive(detection_report, children, process)
        

    # Sort the list by start time
    all_children.sort(key=lambda x: x.process_start_time, reverse=False)

    return all_children


def get_all_parents_recursive(detection_report, parents: List, process: ContextProcess):
    mlog.debug("get_all_parents_recursive - Getting all parents for process UUID: " + str(process.process_uuid) + " and name: " + str(process.process_name))
    mlog.debug(" Current parents: " + str(parents))

    parent_uuid = process.process_parent
    if parent_uuid == "" or parent_uuid == None:
        mlog.debug("get_all_parents_recursive - No parent found process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid))
    else:
        mlog.debug("get_all_parents_recursive - Parent found for process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid) + ". Parent UUID: " + str(parent_uuid) + ". Fetching parent now...")
        parent = bb_get_all_processes_by_uuid(detection_report, parent_uuid)
        if parent == None:
            mlog.warning("get_all_parents_recursive - Parent not found for UUID: " + str(parent_uuid))
            return parents
        mlog.debug("get_all_parents_recursive - ...got Parent name: " + str(parent.process_name) + ". Will append to list and fetch parents for this parent now...")
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