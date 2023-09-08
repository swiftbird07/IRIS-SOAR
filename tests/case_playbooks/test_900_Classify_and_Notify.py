# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_900_Classify_and_Notify playbook.
# ! Be aware that this has to be an online test
import datetime

from case_playbooks.PB_900_Classify_and_Notify import irsoar_can_handle_alert, irsoar_handle_alert
from lib.class_helper import CaseFile, Alert, Rule, ContextAsset


def prepare_test():
    alert = Alert(
        "IBM QRadar",
        "QRadar Offense Test",
        [Rule("1438", "Test Rule")],
        datetime.datetime.now(),
        "This is a test description",
        host_ip="10.21.0.9",
        host_name="test-host",
        uuid="1438",
        device=ContextAsset("MacBook Pro von Martin 14'", "10.21.0.9"),
        severity=50,
    )
    case_file = CaseFile([alert])
    return case_file


def test_irsoar_can_handle_alert():
    case_file = prepare_test()
    # Test the function
    can_handle = irsoar_can_handle_alert(case_file)
    assert can_handle == True, "irsoar_can_handle_alert() should return True for this alert case"


def test_irsoar_handle_alert():
    case_file = prepare_test()
    irsoar_handle_alert(case_file, True)
    assert True == True, "irsoar_handle_alert() should not raise an exception"
