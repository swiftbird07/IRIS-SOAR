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
from playbooks.bb_elastic_process_context import bb_get_complete_process_by_uuid


def test_bb_get_complete_process_by_uuid():
    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    # Prepare the logger
    mlog = logging_helper.Log("playbooks.BB_Elastic_Process_Context")

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

    # Test the function
    process = bb_get_complete_process_by_uuid(detection_report, "N2E5MmQ4NDctM2QxMS00ZDE3LThkZDAtNDRlMTJkYzA3ZmQ4LTE1NzM1NjMtMTY4MjUyNzI2MQ==")
    assert type(process) == ContextProcess, "bb_get_complete_process_by_uuid() should return a ContextProcess object"

    # Print the results
    mlog.info("Process context:")
    mlog.info(process)

#test_bb_get_complete_process_by_uuid()