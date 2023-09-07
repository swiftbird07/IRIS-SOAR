# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_VirusTotal playbook.
# ! Be aware that this has to be an online test

from case_playbooks.PB_110_Generic_VirusTotal import irsoar_can_handle_alert, irsoar_handle_alert
from tests.test_isoar_lib import test_class_helper


def test_irsoar_handle_alert():
    case_file = test_class_helper()  # if an error occurs here, check the test_class_helper() function in tests/test_isoar_lib.py
    irsoar_handle_alert(case_file, False)
    assert True == True, "irsoar_handle_alert() should not raise an exception"
