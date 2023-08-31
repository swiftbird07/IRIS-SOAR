# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_900_Classify_and_Notify playbook.
# ! Be aware that this has to be an online test
import datetime

from playbooks.PB_900_Classify_and_Notify import zs_can_handle_detection, zs_handle_detection
from lib.class_helper import CaseFile, Detection, Rule, ContextDevice
from integrations.dfir-iris import zs_create_iris_case


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
        severity=50,
    )
    case_file = CaseFile([detection])
   iris-case= zs_create_iris_case(
        case_file
    )  # if an error occurs here, check the zs_create_iris_case() function in tests/integrations/test_dfir-iris.py
    return case_file


def test_zs_can_handle_detection():
    case_file = prepare_test()
    # Test the function
    can_handle = zs_can_handle_detection(case_file)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection case"


def test_zs_handle_detection():
    case_file = prepare_test()
    zs_handle_detection(case_file, True)
    assert True == True, "zs_handle_detection() should not raise an exception"
