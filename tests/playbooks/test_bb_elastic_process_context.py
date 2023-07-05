# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the bb_elastic_process_context playbook


import pytest
import zsoar
import os
import datetime
import json

import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, Detection, Rule, ContextProcess, ContextFlow
from lib.config_helper import Config
from playbooks.bb_elastic_process_context import (
    bb_get_all_processes_by_uuid,
    bb_get_all_children,
    bb_get_all_parents,
    bb_make_process_tree_visualisation,
    bb_get_process_network_flows,
)

# Prepare the config
cfg = Config().cfg
integration_config = cfg["integrations"]["elastic_siem"]

# Prepare the logger
mlog = logging_helper.Log("test_bb_elastic_process_context")

# Prepare a CaseFile object
rule = Rule("123", "Some Rule", 0)

TEST_PROCESS_UID = "YjExNmM1NTYtNGNmMi00NTc5LWEwOGQtODU5OTIwMjVmMjNmLTE5MjQ2ODUtMTY4ODA2MTkxOA=="

ruleList = []
ruleList.append(rule)
detection = Detection("456", "Some Detection", ruleList, datetime.datetime.now())

detectionList = []
detectionList.append(detection)
case_file = CaseFile(detectionList)
assert (
    case_file != None
), "CaseFile class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()


def test_bb_get_complete_process_by_uuid():
    # Test the function
    global process
    process = bb_get_all_processes_by_uuid(case_file, TEST_PROCESS_UID)
    assert type(process) == ContextProcess, "bb_get_complete_process_by_uuid() should return a ContextProcess object"

    # Print the results
    mlog.info("Process context:")
    mlog.info(process)


def test_bb_get_all_parents():
    global parents
    parents = bb_get_all_parents(case_file, process=bb_get_all_processes_by_uuid(case_file, TEST_PROCESS_UID))
    assert type(parents) == list, "get_all_parents() should return a list of ContextProcess objects"
    assert len(parents) > 0, "get_all_parents() should return at least one parent"

    uuids = []
    mlog.info("Listing Parents:")
    for parent in parents:
        assert type(parent) == ContextProcess, "get_all_parents() should return a list of ContextProcess objects"
        # Ensure no duplicates
        if parent.process_uuid in uuids:
            # assert False, "get_all_parents() should not return duplicate entries"
            pass
        # Ensure parent is really a parent
        if uuids != [] and parent.process_children != []:
            assert (
                parent.process_children in uuids
            ), "get_all_parents() one of the children of a parent should be in the list of past parents"
        uuids.append(parent.process_uuid)
        mlog.info(str(parent))


def test_bb_get_all_children():
    global children
    children, _ = bb_get_all_children(case_file, process=bb_get_all_processes_by_uuid(case_file, TEST_PROCESS_UID))
    assert type(children) == list, "get_all_children() should return a list of ContextProcess objects"
    assert len(children) > 0, "get_all_children() should return at least one child"

    uuids = []
    mlog.info("Listing children:")
    for child in children:
        assert type(child) == ContextProcess, "get_all_children() should return a list of ContextProcess objects"
        # Ensure no duplicates
        if child.process_uuid in uuids:
            # assert False, "get_all_children() should not return duplicate entries"
            pass
        # Ensure child is really a child
        if uuids != [] and child.process_children != []:
            # assert child.process_children in uuids, "get_all_children() one of the children of a child should be in the list of past children"
            pass
        uuids.append(child.process_uuid)
        mlog.info(str(child))


def test_bb_make_process_tree_visualisation():
    # Test the function
    print(process)
    res = bb_make_process_tree_visualisation(process, parents, children)
    assert type(res) == str, "bb_make_process_tree_visualisation() should return a string"
    # Print the results
    mlog.info("Process tree:")
    mlog.info(res)


def test_bb_get_process_network_flows():
    # Test the function
    res, _ = bb_get_process_network_flows(case_file, process)
    assert type(res) == list, "bb_get_process_network_flows() should return a list of flows"
    assert len(res) > 0, "bb_get_process_network_flows() should return at least one flow"
    for flow in res:
        assert type(flow) == ContextFlow, "bb_get_process_network_flows() should return a list of flows"
    # Print the results
    mlog.info("Process network flows:")
    mlog.info(res)


#
# o
# ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTEwOTMyLTEzMzI3MTExMjQ2LjE5NDk4MTMwMA==
# ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTEwNjEyLTEzMzI3MTExMjQ2LjgwMzE2NzAw
# ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTEwNjgtMTMzMjcxMTExODkuMjQxNTQ1OTAw
