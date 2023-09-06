# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_VirusTotal playbook.
# ! Be aware that this has to be an online test

from integrations.dfir-iris import irsoar_create_iris_case
from case_playbooks.PB_110_Generic_VirusTotal import irsoar_can_handle_alert, irsoar_handle_alert
from tests.test_isoar_lib import test_class_helper


def test_irsoar_can_handle_alert():
    case_file = test_class_helper()  # if an error occurs here, check the test_class_helper() function in tests/test_isoar_lib.py
   iris-case= irsoar_create_iris_case(
        case_file
    )  # if an error occurs here, check the irsoar_create_iris_case() function in tests/integrations/test_dfir-iris.py

    # Test the function
    can_handle = irsoar_can_handle_alert(case_file)
    assert can_handle == True, "irsoar_can_handle_alert() should return True for this alert case"


def test_irsoar_handle_alert():
    case_file = test_class_helper()  # if an error occurs here, check the test_class_helper() function in tests/test_isoar_lib.py
   iris-case= irsoar_create_iris_case(
        case_file
    )  # if an error occurs here, check the irsoar_create_iris_case() function in tests/integrations/test_dfir-iris.py

    irsoar_handle_alert(case_file, False)
    assert True == True, "irsoar_handle_alert() should not raise an exception"
