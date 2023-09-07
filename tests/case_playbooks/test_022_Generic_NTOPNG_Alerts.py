# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_020_Generic_NTOP-NG_Alerts playbook.
# ! Be aware that this has to be an online test
import datetime

from case_playbooks.PB_022_Generic_NTOPNG_Alerts import irsoar_can_handle_alert, irsoar_handle_alert
from lib.class_helper import CaseFile, Alert, Rule, ContextLog
from integrations.ibm_qradar import irsoar_provide_context_for_alerts

OFFENSE_ID = "1539"


def prepare_test():
    alert = Alert(
        "IBM QRadar",
        "QRadar NTOP-NG Offense Test",
        [Rule("1438", "Test Rule")],
        datetime.datetime.now(),
        "This is a test description",
        host_ip="123.123.123.123",
        host_name="test-host",
        uuid="1438",
    )
    case_file = CaseFile([alert])

    iris_case_number = irsoar_create_iris_case(
        case_file
    )  # if an error occurs here, check the irsoar_create_iris_case() function in tests/integrations/test_dfir-iris.py
    case_file.add_context(irsoar_get_iris_case_by_number(iris_case_number))

    alertArray = irsoar_provide_context_for_alerts(
        case_file, ContextLog, TEST=True, search_type="offense", search_value=OFFENSE_ID
    )
    for log in alertArray:
        case_file.context_logs.append(log)
    return case_file


def test_irsoar_can_handle_alert():
    case_file = prepare_test()

    # Test the function
    can_handle = irsoar_can_handle_alert(case_file)
    assert can_handle == True, "irsoar_can_handle_alert() should return True for this alert case"


def test_irsoar_handle_alert():
    case_file = prepare_test()

    irsoar_handle_alert(case_file, False)
    assert True == True, "irsoar_handle_alert() should not raise an exception"


test_irsoar_can_handle_alert()
