# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_QRadar_Offenses playbook.
# ! Be aware that this has to be an online test
import datetime

from case_playbooks.PB_011_Generic_QRadar_Offenses import irsoar_can_handle_alert, irsoar_handle_alert
from lib.class_helper import CaseFile, Alert, Rule

alert = Alert(
    "IBM QRadar",
    "QRadar Offense Test",
    [Rule("1438", "Test Rule")],
    datetime.datetime.now(),
    "This is a test description",
    host_ip="10.20.1.6",
    host_name="test-host",
    uuid="1438",
)
case_file = CaseFile([alert])


def test_irsoar_can_handle_alert():
    # Test the function
    can_handle = irsoar_can_handle_alert(case_file)
    assert can_handle == True, "irsoar_can_handle_alert() should return True for this alert case"


def test_irsoar_handle_alert():
    irsoar_handle_alert(case_file, False)
    assert True == True, "irsoar_handle_alert() should not raise an exception"
