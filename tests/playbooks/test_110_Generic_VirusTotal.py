# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_VirusTotal playbook.
# ! Be aware that this has to be an online 

import pytest
import zsoar
import os
import datetime
import json

import lib.logging_helper as logging_helper
from lib.class_helper import DetectionReport, Detection, Rule, ContextProcess
from lib.config_helper import Config
from integrations.znuny_otrs import zs_create_ticket
from playbooks.PB_110_Generic_VirusTotal import zs_can_handle_detection, zs_handle_detection
from tests.test_zsoar_lib import test_class_helper

def test_zs_can_handle_detection():
    detection_report = test_class_helper() # if an error occurs here, check the test_class_helper() function in tests/test_zsoar_lib.py
    ticket = zs_create_ticket(detection_report) # if an error occurs here, check the zs_create_ticket() function in tests/integrations/test_znuny_otrs.py

    # Test the function
    can_handle = zs_can_handle_detection(detection_report)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection report"

def test_zs_handle_detection():
    detection_report = test_class_helper() # if an error occurs here, check the test_class_helper() function in tests/test_zsoar_lib.py
    ticket = zs_create_ticket(detection_report) # if an error occurs here, check the zs_create_ticket() function in tests/integrations/test_znuny_otrs.py

    zs_handle_detection(detection_report, False)
    assert True == True, "zs_handle_detection() should not raise an exception"