# Building Block for Z-SOAR Playbooks
# Created by: Martin Offermann
#
# This is a building block used by Z-SOAR Playbooks
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
BB_NAME = "BB_Elastic_Process_Context"
BB_VERSION = "1.0.0"
BB_AUTHOR = "Martin Offermann"
BB_LICENSE = "MIT"
BB_ENABLED = True

THRESHOLD_MAX_PROCESS_CHILDREN = 1000 # Maximum number of children to fetch for each process
THRESHOLD_MAX_NETWORK_FLOWS = 500 # Maximum number of network flows to fetch for each process
THRESHOLD_MAX_FILE_EVENTS = 500 # Maximum number of files to fetch for each process
THRESHOLD_MAX_REGISTRY_EVENTS = 500 # Maximum number of registry events to fetch for each process

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
from lib.class_helper import DetectionReport, ContextProcess, ContextFlow, ContextFile, ContextRegistry
from integrations.elastic_siem import zs_provide_context_for_detections
from lib.config_helper import Config

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
    processes = zs_provide_context_for_detections(integration_config, detection_report, ContextProcess, search_value=uuid, maxContext=-1, TEST=False, UUID_is_parent=children)
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
        return children, done_hashes
    if type(new_children) != list and type(new_children) == ContextProcess:
        mlog.debug("get_all_children_recursive - Only one child found for process name " + str(process.process_name) + " with UUID: " + str(process.process_uuid))
        new_children = [new_children]


    for child in new_children:
        if child.process_uuid == process.process_uuid:
            mlog.error("get_all_children_recursive - ! Stopped possible endless loop: Child UUID is the same as current process UUID ! Skipping this child.")
            continue

        if child == "" or child == None or type(child) != ContextProcess:
            mlog.debug("get_all_children_recursive - Skipping a found 'child' because it is empty or not a ContextProcess object.")
            continue
        else:
            mlog.debug("get_all_children_recursive - Child found for process name " + str(process.process_name) + " with child name: " + str(child.process_name) + ". child UUID: " + str(child.process_uuid) + ". Adding it to current process as child and DetectionReport context...")
            process.process_children.append(child)
            detection_report.add_context(child)
            if  not all_process_events and (child.process_sha256 in done_hashes):
                mlog.debug("get_all_children_recursive - Skipping adding child to return list because a process with the same hash is already in it. Child SHA256: " + str(child.process_sha256))
                continue
            mlog.debug("get_all_children_recursive - Will append " + str(child.process_name) +" to return list and fetch children for this child now...")
            children.append(child)
            done_hashes.append(child.process_sha256)
            get_all_children_recursive(detection_report, children, child)
    return children, done_hashes


def bb_get_all_children(detection_report: DetectionReport, process: ContextProcess) -> List[ContextProcess]:
    """Returns all children (meaning all leafs) of a process

    :param detection_report: A DetectionReport object
    :param process: The process to get the children for

    Be aware that the context is already added to the DetectionReport object when calling this function.
    :return: A list of ContextProcess objects
    """
    children = []
    thrown_process_count = 0
    if process != None:
        all_children, _ = get_all_children_recursive(detection_report, children, process, done_hashes=[], all_process_events=False)
    else:
        mlog.warning("bb_get_all_children - Process is None. Returning empty list.")
        return [], 0
    
    for child in all_children:
        detection_report.add_context(child)

    # Sort the list by start time
    all_children.sort(key=lambda x: x.process_start_time, reverse=False)

    if len(all_children) > THRESHOLD_MAX_PROCESS_CHILDREN:
        mlog.warning("bb_get_all_children - More than " + str(THRESHOLD_MAX_PROCESS_CHILDREN) + " children found for process: " + str(process.process_name) + ". Only returning the first " + str(THRESHOLD_MAX_PROCESS_CHILDREN) + " children.")
        thrown_process_count = len(all_children) - THRESHOLD_MAX_PROCESS_CHILDREN
        all_children = all_children[:THRESHOLD_MAX_PROCESS_CHILDREN]

    return all_children, thrown_process_count


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
            mlog.warning("get_all_parents_recursive - Parent process not found for UUID: " + str(parent_uuid))
            return parents
        mlog.debug("get_all_parents_recursive - ...got Parent name: " + str(parent.process_name) + ". Will append to list and fetch parents for this parent now...")
        parents.append(parent)
        get_all_parents_recursive(detection_report, parents, parent)
    return parents


def bb_get_all_parents(detection_report: DetectionReport, process: ContextProcess) -> List[ContextProcess]:
    """Returns all parents (meaning all root nodes, without all their childs) of a process

    :param detection_report: A DetectionReport object
    :param process: The process to get the parents for

    Be aware that the context is already added to the DetectionReport object when calling this function.
    :return: A list of ContextProcess objects
    """
    mlog.debug("get_all_parents - Getting all parents for process: " + str(process))

    parents = []
    if process != None:
        all_parents = get_all_parents_recursive(detection_report, parents, process)
    else:
        mlog.warning("get_all_parents - Process is None. Returning empty list.")
        return []
    
    # Remove parents with the same Hash as the process
    all_parents = [parent for parent in all_parents if parent.process_uuid != process.process_uuid]

    for parent in all_parents:
        detection_report.add_context(parent)

    # Sort the list by start time from newest to oldest
    try:
        all_parents.sort(key=lambda x: x.process_start_time, reverse=True)
    except:
        mlog.warning("get_all_parents - Could not sort list of parents by start time. Will return unsorted list.")

    return parents

def bb_make_process_tree_visualisation(focus_process: ContextProcess, parents: List[ContextProcess], children: List[ContextProcess]) -> str:
    """Returns a visualisation of the process tree

    :param process: The process to create the tree for
    :param parents: The parents of the process
    :param children: The children of the process

    :return: A string containing the visualisation of the process tree
    """
    mlog.debug("bb_make_process_tree_visualisation - Creating process tree visualisation for process: " + str(focus_process.process_name))
    from treelib import Node, Tree, exceptions
    tree = Tree()
    # Create tree nodes for all parents
    for j in range(0, len(parents) - 0):
        try:
            i = len(parents) - j - 1
            process = parents[i]
            if i == len(parents) - 1:
                mlog.debug("bb_make_process_tree_visualisation - Creating root node for process: " + str(process.process_name) + " (" + str(process.process_sha256) + ")")
                root_uid = process.process_sha256
                if root_uid is None:
                    root_uid = "0"
                tree.create_node(process.process_name + " (" + str(process.process_id) + ")", root_uid)
            else:
                parent = parents[i+1]
                parent_sha = parent.process_sha256
                
                if parent.process_sha256 is None:
                    mlog.warning(f"bb_make_process_tree_visualisation - Duplicate root node found! Process: " + str(process.process_name) + " (" + str(process.process_sha256) + "). Linking to first root node...")
                    parent_sha = root_uid
                mlog.debug("bb_make_process_tree_visualisation - Creating node for process: " + str(process.process_name) + " (" + str(process.process_sha256) + ") " + " with parent: " + str(parent.process_name) + " (" + str(parent_sha) + ")")
                tree.create_node(process.process_name + " (" + str(process.process_id) + ")", process.process_sha256, parent=parent_sha)
        except Exception as e:
            mlog.error("bb_make_process_tree_visualisation - Error in Parent Processes: " + str(e))

    # Create detected process node
    try:
        if len(parents) == 0:
            tree.create_node(focus_process.process_name + " (" + str(focus_process.process_id) + ")", focus_process.process_sha256)
        else:
            parent_sha=parents[0].process_sha256
            if focus_process.process_sha256 == parent_sha: # Weird bug revolving around how Elastic SIEM handles and defines parent/child EntityIDs
                parent_sha = parents[1].process_sha256
                if focus_process.process_sha256 == parent_sha or parent_sha == None: # Sanity check
                    parent_sha = "0"

            parent_name = parents[0].process_name
            if parent_name == None:
                parent_name = "Unknown"

            #mlog.debug("bb_make_process_tree_visualisation - Creating node for detected process: " + str(process.process_name) + " (" + str(process.process_sha256) + ") " + " with parent: " + str(parent_name) + " (" + str(parent_sha) + ")")
            tree.create_node(focus_process.process_name + " (" + str(focus_process.process_id) + ")", focus_process.process_sha256, parent=parent_sha)
    except Exception as e:
        mlog.error("bb_make_process_tree_visualisation - Error in Detected Process: " + str(e))
 

    # Create tree nodes for all children
    for i in range(0, len(children)):
        try:
            process = children[i]
            if i == 0:
                parent_sha = focus_process.process_sha256
            else:
                parent_sha = process.process_parent

            #mlog.debug("bb_make_process_tree_visualisation - Creating node for process: " + str(process.process_name) + " (" + str(process.process_uuid) + ") " + " with parent: "  + " (" + str(parent_sha) + ")")
            try:
                tree.create_node(process.process_name + " (" + str(process.process_id) + ")", process.process_uuid, parent=parent_sha)
            except exceptions.NodeIDAbsentError:
                tree.create_node(process.process_name + " (" + str(process.process_id) + ")", process.process_uuid, parent=focus_process.process_sha256)

        except Exception as e:
            mlog.error("bb_make_process_tree_visualisation - Error in Child Processes: " + str(e))

    tree_str = tree.show(stdout=False)
    tree.show()
    mlog.debug("bb_make_process_tree_visualisation - Returning process tree visualisation: \n" + tree_str)
    return tree_str

def bb_get_process_network_flows(detection_report: DetectionReport, process: ContextProcess) -> ContextFlow:
    """Returns all network flows for a process.
       Context is automatically added to the DetectionReport object.
       
       :param detection_report: The Detection Report
       :param process: The process to get the network flows for
       
       :return: A list of ContextFlow objects
    """
    mlog.debug("get_network_flows - Getting network flows for process: " + str(process))
    uuid = process.process_uuid
    network_flows = []
    thrown_flows_count = 0
    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    network_flows: List[ContextFlow] = zs_provide_context_for_detections(integration_config, detection_report, ContextFlow, False, uuid, False)
    if network_flows == None or len(network_flows) == 0:
        mlog.debug("get_network_flows - No network flows found for process: " + str(process.process_name))
        return None, 0
    else:
        if len(network_flows) > THRESHOLD_MAX_NETWORK_FLOWS:
            mlog.warning("get_network_flows - Too many network flows found for process: " + str(process.process_name) + ". Limiting to " + str(THRESHOLD_MAX_NETWORK_FLOWS) + " flows...")
            thrown_flows_count = len(network_flows) - THRESHOLD_MAX_NETWORK_FLOWS
            network_flows = network_flows[:THRESHOLD_MAX_NETWORK_FLOWS]

        mlog.debug("get_network_flows - Returning " + str(len(network_flows)) + " network flows for process: " + str(process.process_name))
        for flow in network_flows:
            # Add process context to the flow
            flow.process_id = process.process_id
            flow.process_name = process.process_name
            flow.process_uuid = process.process_uuid

            detection_report.add_context(flow)

    return network_flows, thrown_flows_count

def bb_get_process_file_events(detection_report: DetectionReport, process: ContextProcess) -> ContextFile:
    """Returns all file events for a process.
       Context is automatically added to the DetectionReport object.
       
       :param detection_report: The Detection Report
       :param process: The process to get the file events for
       
       :return: A list of ContextFile objects
    """
    mlog.debug("get_file_events - Getting file events for process: " + str(process))
    uuid = process.process_uuid
    file_events = []
    thrown_events_count = 0
    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    file_events: List[ContextFile] = zs_provide_context_for_detections(integration_config, detection_report, ContextFile, False, uuid, False)
    if file_events == None or len(file_events) == 0:
        mlog.debug("get_file_events - No file events found for process: " + str(process.process_name))
        return None, 0
    else:
        if len(file_events) > THRESHOLD_MAX_FILE_EVENTS:
            mlog.warning("get_file_events - Too many file events found for process: " + str(process.process_name) + ". Limiting to " + str(THRESHOLD_MAX_FILE_EVENTS) + " events...")
            thrown_events_count = len(file_events) - THRESHOLD_MAX_FILE_EVENTS
            file_events = file_events[:THRESHOLD_MAX_FILE_EVENTS]

        mlog.debug("get_file_events - Returning " + str(len(file_events)) + " file events for process: " + str(process.process_name))
        for event in file_events:
            # Add process context to the event
            event.process_id = process.process_uuid
            event.process_name = process.process_name
            event.process_uuid = process.process_uuid

            detection_report.add_context(event)

    return file_events, thrown_events_count

def bb_get_process_registry_events(detection_report: DetectionReport, process: ContextProcess) -> ContextRegistry:
    """Returns all registry events for a process.
       Context is automatically added to the DetectionReport object.
       
       :param detection_report: The Detection Report
       :param process: The process to get the registry events for
       
       :return: A list of ContextRegistry objects
    """
    mlog.debug("get_registry_events - Getting registry events for process: " + str(process))
    uuid = process.process_uuid
    registry_events = []
    thrown_events_count = 0
    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    registry_events: List[ContextRegistry] = zs_provide_context_for_detections(integration_config, detection_report, ContextRegistry, False, uuid, False)
    if registry_events == None or len(registry_events) == 0:
        mlog.debug("get_registry_events - No registry events found for process: " + str(process.process_name))
        return None, 0
    else:
        if len(registry_events) > THRESHOLD_MAX_REGISTRY_EVENTS:
            mlog.warning("get_registry_events - Too many registry events found for process: " + str(process.process_name) + ". Limiting to " + str(THRESHOLD_MAX_REGISTRY_EVENTS) + " events...")
            thrown_events_count = len(registry_events) - THRESHOLD_MAX_REGISTRY_EVENTS
            registry_events = registry_events[:THRESHOLD_MAX_REGISTRY_EVENTS]

        mlog.debug("get_registry_events - Returning " + str(len(registry_events)) + " registry events for process: " + str(process.process_name))
        for event in registry_events:
            # Add process context to the event
            event.process_id = process.process_uuid
            event.process_name = process.process_name
            event.process_uuid = process.process_uuid

            detection_report.add_context(event)

    return registry_events, thrown_events_count