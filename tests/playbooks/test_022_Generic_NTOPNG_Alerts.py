# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_020_Generic_NTOP-NG_Alerts playbook.
# ! Be aware that this has to be an online test
import datetime

from playbooks.PB_022_Generic_NTOPNG_Alerts import zs_can_handle_detection, zs_handle_detection
from lib.class_helper import CaseFile, Detection, Rule, ContextLog
from integrations.ibm_qradar import zs_provide_context_for_detections
from integrations.dfir-iris import zs_create_iris_case, zs_get_iris_case_by_number

OFFENSE_ID = "1539"


def prepare_test():
    detection = Detection(
        "IBM QRadar",
        "QRadar NTOP-NG Offense Test",
        [Rule("1438", "Test Rule")],
        datetime.datetime.now(),
        "This is a test description",
        host_ip="123.123.123.123",
        host_name="test-host",
        uuid="1438",
    )
    case_file = CaseFile([detection])

    iris_case_number = zs_create_iris_case(
        case_file
    )  # if an error occurs here, check the zs_create_iris_case() function in tests/integrations/test_dfir-iris.py
    case_file.add_context(zs_get_iris_case_by_number(iris_case_number))

    detectionArray = zs_provide_context_for_detections(
        case_file, ContextLog, TEST=True, search_type="offense", search_value=OFFENSE_ID
    )
    for log in detectionArray:
        case_file.context_logs.append(log)
    return case_file


def test_zs_can_handle_detection():
    case_file = prepare_test()

    # Test the function
    can_handle = zs_can_handle_detection(case_file)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection case"


def test_zs_handle_detection():
    case_file = prepare_test()

    zs_handle_detection(case_file, False)
    assert True == True, "zs_handle_detection() should not raise an exception"


test_zs_can_handle_detection()
