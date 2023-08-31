# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_Elastic_Alerts playbook


import pytest
import isoar
import os
import datetime
import json

import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, Detection, Rule, ContextProcess
from lib.config_helper import Config
from playbooks.PB_010_Generic_Elastic_Alerts import zs_can_handle_detection, zs_handle_detection
from playbooks.bb_elastic_process_context import bb_get_all_processes_by_uuid

TEST_ONLINE = True  # Set this to True to make changes to Znuny while testing
TEST_PROCESS_UID = "YjExNmM1NTYtNGNmMi00NTc5LWEwOGQtODU5OTIwMjVmMjNmLTE5MjQ2ODUtMTY4ODA2MTkxOA=="


def prepare_test():
    # Prepare the config
    cfg = Config().cfg
    integration_config = cfg["integrations"]["dfir-iris"]

    # Prepare the logger
    mlog = logging_helper.Log("test_PB_010_Generic_Elastic_Alerts")

    # Prepare a CaseFile object
    rule = Rule("123", "Some Rule", 0)

    ruleList = []
    ruleList.append(rule)
    detection = Detection("010 Detection", "Some Detection", ruleList, datetime.datetime.now())
    detection.vendor_id = "elastic_siem"

    detectionList = []
    detectionList.append(detection)
    case_file = CaseFile(detectionList)

    process = bb_get_all_processes_by_uuid(case_file, TEST_PROCESS_UID)

    case_file.add_context(process)
    detection.process = process

    assert (
        case_file != None
    ), "CaseFile class could not be initialized"  # Sanity check - should be already tested by test_isoar_lib.py -> test_class_helper()
    return case_file


def test_zs_can_handle_detection():
    case_file = prepare_test()
    # Test the function
    can_handle = zs_can_handle_detection(case_file)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection case"


def test_zs_handle_detection():
    case_file = prepare_test()
    zs_handle_detection(case_file, not TEST_ONLINE)
    assert True == True, "zs_handle_detection() should not raise an exception"
