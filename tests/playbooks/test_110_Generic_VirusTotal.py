# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the PB_010_Generic_VirusTotal playbook.
# ! Be aware that this has to be an online test

from integrations.dfir-iris import zs_create_iris_case
from playbooks.PB_110_Generic_VirusTotal import zs_can_handle_detection, zs_handle_detection
from tests.test_isoar_lib import test_class_helper


def test_zs_can_handle_detection():
    case_file = test_class_helper()  # if an error occurs here, check the test_class_helper() function in tests/test_isoar_lib.py
   iris-case= zs_create_iris_case(
        case_file
    )  # if an error occurs here, check the zs_create_iris_case() function in tests/integrations/test_dfir-iris.py

    # Test the function
    can_handle = zs_can_handle_detection(case_file)
    assert can_handle == True, "zs_can_handle_detection() should return True for this detection case"


def test_zs_handle_detection():
    case_file = test_class_helper()  # if an error occurs here, check the test_class_helper() function in tests/test_isoar_lib.py
   iris-case= zs_create_iris_case(
        case_file
    )  # if an error occurs here, check the zs_create_iris_case() function in tests/integrations/test_dfir-iris.py

    zs_handle_detection(case_file, False)
    assert True == True, "zs_handle_detection() should not raise an exception"
