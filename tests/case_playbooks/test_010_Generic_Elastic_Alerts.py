# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_Elastic_Alerts playbook


import pytest
import isoar
import os
import datetime
import json

import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, Alert, Rule, ContextProcess
from lib.config_helper import Config
from case_playbooks.PB_010_Generic_Elastic_Alerts import irsoar_can_handle_alert, irsoar_handle_alert
from case_playbooks.bb_elastic_process_context import bb_get_all_processes_by_uuid

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
    alert = Alert("010 Alert", "Some Alert", ruleList, datetime.datetime.now())
    alert.vendor_id = "elastic_siem"

    alertList = []
    alertList.append(alert)
    case_file = CaseFile(alertList)

    process = bb_get_all_processes_by_uuid(case_file, TEST_PROCESS_UID)

    case_file.add_context(process)
    alert.process = process

    assert (
        case_file != None
    ), "CaseFile class could not be initialized"  # Sanity check - should be already tested by test_isoar_lib.py -> test_class_helper()
    return case_file


def test_irsoar_can_handle_alert():
    case_file = prepare_test()
    # Test the function
    can_handle = irsoar_can_handle_alert(case_file)
    assert can_handle == True, "irsoar_can_handle_alert() should return True for this alert case"


def test_irsoar_handle_alert():
    case_file = prepare_test()
    irsoar_handle_alert(case_file, not TEST_ONLINE)
    assert True == True, "irsoar_handle_alert() should not raise an exception"
