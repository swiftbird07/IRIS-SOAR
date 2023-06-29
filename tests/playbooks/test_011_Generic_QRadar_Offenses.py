# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_QRadar_Offenses playbook.
# ! Be aware that this has to be an online test
import datetime

from playbooks.PB_011_Generic_QRadar_Offenses import zs_can_handle_detection, zs_handle_detection
from lib.class_helper import DetectionReport, Detection, Rule

detection = Detection(
    "IBM QRadar",
    "QRadar Offense Test",
    [Rule("1438", "Test Rule")],
    datetime.datetime.now(),
    "This is a test description",
    host_ip="10.20.1.6",
    host_name="test-host",
    uuid="1438",
)
detection_report = DetectionReport([detection])


def test_zs_can_handle_detection():
    # Test the function
    can_handle = zs_can_handle_detection(detection_report)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection report"


def test_zs_handle_detection():
    zs_handle_detection(detection_report, False)
    assert True == True, "zs_handle_detection() should not raise an exception"
