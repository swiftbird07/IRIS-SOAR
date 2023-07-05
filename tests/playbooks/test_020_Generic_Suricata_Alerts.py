# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_020_Generic_Suricata_Alerts playbook.
# ! Be aware that this has to be an online test
import datetime

from playbooks.PB_020_Generic_Suricata_Alerts import zs_can_handle_detection, zs_handle_detection
from lib.class_helper import CaseFile, Detection, Rule, ContextLog
from integrations.ibm_qradar import zs_provide_context_for_detections
from integrations.znuny_otrs import zs_create_ticket

OFFENSE_ID = "1454"


def prepare_test():
    detection = Detection(
        "IBM QRadar",
        "QRadar Offense Test",
        [Rule("1438", "Test Rule")],
        datetime.datetime.now(),
        "This is a test description",
        host_ip="123.123.123.123",
        host_name="test-host",
        uuid="1438",
    )
    case_file = CaseFile([detection])

    ticket = zs_create_ticket(
        case_file
    )  # if an error occurs here, check the zs_create_ticket() function in tests/integrations/test_znuny_otrs.py
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
