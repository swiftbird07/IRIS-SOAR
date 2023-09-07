# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_Create_Case_for_Multiple_Host_Alerts alert-playbook.
# ! Be aware that this has to be an online test
import datetime

from alert_playbooks.PB_Create_Case_for_Multiple_Host_Alerts import irsoar_handle_alert
from lib.class_helper import CaseFile, Alert, Rule

alert1 = Alert(
    "IBM QRadar",
    "QRadar Offense Test A",
    [Rule("1438", "Test Rule")],
    datetime.datetime.now(),
    "This is a test description",
    host_ip="10.20.1.6",
    host_name="test-host-A",
    uuid="1438",
)

alert2 = Alert(
    "IBM QRadar",
    "QRadar Offense Test B",
    [Rule("1438", "Test Rule")],
    datetime.datetime.now(),
    "This is a test description",
    host_ip="10.20.1.6",
    host_name="test-host-A",
    uuid="1438",
)

alert3 = Alert(
    "IBM QRadar",
    "QRadar Offense Test C",
    [Rule("1438", "Test Rule")],
    datetime.datetime.now(),
    "This is a test description",
    host_ip="10.20.1.6",
    host_name="test-host-B",
    uuid="1438",
)

def test_irsoar_handle_alert():
    irsoar_handle_alert([alert1, alert2, alert3], True)
    assert True == True, "irsoar_handle_alert() should not raise an exception"
