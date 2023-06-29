# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_021_Advanced_Elastic_Context playbook.
# ! Be aware that this has to be an online test
import datetime

from playbooks.PB_021_Advanced_Elastic_Context import zs_can_handle_detection, zs_handle_detection
from lib.class_helper import DetectionReport, Detection, Rule, ContextDevice
from integrations.znuny_otrs import zs_create_ticket


def prepare_test():
    detection = Detection(
        "IBM QRadar",
        "QRadar Offense Test",
        [Rule("1438", "Test Rule")],
        datetime.datetime.now(),
        "This is a test description",
        host_ip="10.21.0.9",
        host_name="test-host",
        uuid="1438",
        device=ContextDevice("MacBook Pro von Martin 14'", "10.21.0.9"),
    )
    detection_report = DetectionReport([detection])
    ticket = zs_create_ticket(
        detection_report
    )  # if an error occurs here, check the zs_create_ticket() function in tests/integrations/test_znuny_otrs.py
    return detection_report


def test_zs_can_handle_detection():
    detection_report = prepare_test()
    # Test the function
    can_handle = zs_can_handle_detection(detection_report)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection report"


def test_zs_handle_detection():
    detection_report = prepare_test()
    zs_handle_detection(detection_report, False)
    assert True == True, "zs_handle_detection() should not raise an exception"
