# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the bb_elastic_process_context playbook.def test_bb_get_complete_process_by_uuid():


import pytest
import zsoar
import os
import datetime
import json

import lib.logging_helper as logging_helper
from lib.class_helper import DetectionReport, Detection, Rule, ContextProcess
from lib.config_helper import Config
from playbooks.bb_elastic_process_context import bb_get_complete_process_by_uuid, bb_get_all_children, bb_get_all_parents

# Prepare the config
cfg = Config().cfg
integration_config = cfg["integrations"]["elastic_siem"]

# Prepare the logger
mlog = logging_helper.Log("test_bb_elastic_process_context")

# Prepare a DetectionReport object
rule = Rule("123", "Some Rule", 0)

ruleList = []
ruleList.append(rule)
detection = Detection("456", "Some Detection", ruleList, datetime.datetime.now())

detectionList = []
detectionList.append(detection)
detection_report = DetectionReport(detectionList)
assert (
    detection_report != None
), "DetectionReport class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()



def test_bb_get_complete_process_by_uuid():
    # Test the function
    process = bb_get_complete_process_by_uuid(detection_report, "ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTE3MzUyLTEzMzI3MTExMjgwLjMwNjUwNTQwMA==")
    assert type(process) == ContextProcess, "bb_get_complete_process_by_uuid() should return a ContextProcess object"

    # Print the results
    mlog.info("Process context:")
    mlog.info(process)

def test_bb_get_all_parents():
    parents = bb_get_all_parents(detection_report, process=bb_get_complete_process_by_uuid(detection_report, "ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTE3MzUyLTEzMzI3MTExMjgwLjMwNjUwNTQwMA=="))
    assert type(parents) == list, "get_all_parents() should return a list of ContextProcess objects"
    assert len(parents) > 0, "get_all_parents() should return at least one parent"

    uuids = []
    mlog.info("Listing Parents:")
    for parent in parents:
        assert type(parent) == ContextProcess, "get_all_parents() should return a list of ContextProcess objects"
        # Ensure no duplicates
        if parent.process_uuid in uuids:
            #assert False, "get_all_parents() should not return duplicate entries"
            pass
        # Ensure parent is really a parent
        if uuids != [] and parent.process_children != []:
            assert parent.process_children in uuids, "get_all_parents() one of the children of a parent should be in the list of past parents"
        uuids.append(parent.process_uuid)
        mlog.info(str(parent))

# 
# o
# ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTEwOTMyLTEzMzI3MTExMjQ2LjE5NDk4MTMwMA==
# ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTEwNjEyLTEzMzI3MTExMjQ2LjgwMzE2NzAw
# ZTM0MWJhZTMtMmI0YS00ODY2LTk3MjItYjE0ZmNkY2RiNWYzLTEwNjgtMTMzMjcxMTExODkuMjQxNTQ1OTAw

#test_bb_get_complete_process_by_uuid()
test_bb_get_all_parents()