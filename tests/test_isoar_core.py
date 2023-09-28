# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the isoar.py module.
# It will test if the prvided arguments are working as expected.

from asyncio import sleep
import builtins
import sys
import os
import mock
import pytest
import subprocess as subp
import copy


def test_import():
    """Tests if the module can be imported.

    Args:
        None

    Returns:
        None
    """
    try:
        import isoar
        from isoar import logging_helper

        return
    except ImportError:
        pytest.fail("The module can not be imported.")


import os
import sys

# Add the parent directory of the test file to the Python path
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Now you can import the isoar module
import isoar


def test_arg_parsing():
    """Tests parsing of arguments.

    Args:
        None

    Returns:
        None
    """
    # Test if the parser can be initialized
    try:
        parser = isoar.add_arguments()
    except Exception as e:
        pytest.fail("The parser can not be initialized: {}".format(e))

    # Test if the parser can be used
    try:
        sys.argv = ["--version"]
        parser.parse_args()
    except Exception as e:
        pytest.fail("The parser can not be used: {}".format(e))
    return


def test_setup():
    """Tests the setup function.

    Args:
        None

    Returns:
        None
    """
    cfg = isoar.config_helper.Config().cfg
    tmp = copy.deepcopy(cfg)

    isoar.config_helper.save_config(cfg)

    # Following sub-test doesnt work, because a wrong input is ignored and the input is asked again. Therefore the test would hang:

    # with mock.patch.object(builtins, "input", lambda: "19"):
    #     isoar.setup(0)
    # cfg = isoar.config_helper.Config().cfg
    # assert cfg["setup"]["setup_step"] == 0, "The setup step accepted an invalid input."

    # Test vaild input True/False:

    cfg["setup"]["setup_step"] = 1
    cfg["daemon"]["enabled"] = False
    isoar.config_helper.save_config(cfg)

    with mock.patch.object(builtins, "input", lambda: "y"):
        isoar.setup(1, continue_steps=False)
    cfg = isoar.config_helper.Config().cfg
    assert cfg["setup"]["setup_step"] == 2, "The setup step didn't progress after valid input (bool)."
    assert cfg["daemon"]["enabled"] == True, "The setup step didn't save new value (bool)."

    # Test vaild input Integer
    cfg["setup"]["setup_step"] = 2
    cfg["daemon"]["interval"] = 1
    isoar.config_helper.save_config(cfg)

    with mock.patch.object(builtins, "input", lambda: 12):
        isoar.setup(2, continue_steps=False)
    cfg = isoar.config_helper.Config().cfg
    assert cfg["daemon"]["interval"] == 12, "The setup step didn't save new value (int)."
    assert cfg["setup"]["setup_step"] == 3, "The setup step didn't progress after valid input (int)."

    # Reset to original config
    assert isoar.config_helper.save_config(tmp) == True, "Resetting config to original failed (test_setup)."


def test_startup_daemon():
    """Tests the startup function for spawning a daemon.

    Args:
        None

    Returns:
        None
    """
    # Stop daemon first if running
    try:
        isoar.stop(isoar.logging_helper.Log("isoar_test_core"))
    except:
        pass  # Stop errors not in scope of this test

    # Temporarily enable the daemon
    cfg = isoar.config_helper.Config().cfg
    tmp = copy.deepcopy(cfg)

    cfg["daemon"]["enabled"] = True
    isoar.config_helper.save_config(cfg)

    # Test if the daemon can be started
    mlog = isoar.logging_helper.Log("isoar_test_core")
    isoar.startup(mlog, True, False)
    assert isoar.get_script_pid(mlog, "isoar_daemon.py") > 0, "The daemon was not started."

    # Reset to original config
    assert isoar.config_helper.save_config(tmp) == True, "Resetting config to original failed (test_startup_daemon)."


def test_stop():
    """Tests the stop function.

    Args:
        None

    Returns:
        None
    """
    mlog = isoar.logging_helper.Log("isoar_test_core")
    isoar.stop(mlog)
    assert isoar.get_script_pid(mlog, "isoar_daemon.py") == -1, "The daemon was not stopped."


def test_daemon():
    """Tests the daemon function. Note that this does not test the called isoar_worker.

    Args:
        None

    Returns:
        None
    """
    try:
        isoar.isoar_daemon.main(TEST_CALL=True)
    except Exception as e:
        pytest.fail("The daemon function failed: {}".format(e))


def test_alert_collector():
    pass  # TODO: Implement


def test_case_worker():
    """Tests the worker function.

    Args:
        None

    Returns:
        None
    """
    config = isoar.config_helper.Config().cfg
    mlog = isoar.logging_helper.Log("isoar_test_core")

    try:
        isoar.isoar_worker.main(config)
    except Exception as e:
        pytest.fail("The worker function failed: {}".format(e))

    # Test check_module_exists and check_module_has_function
    assert isoar.isoar_worker.check_module_exists("elastic_siem") == True, "elastic_siem module 'does not exist'"
    assert isoar.isoar_worker.check_module_exists("some_invalid_module") == False, "some_invalid_module module exists"
    assert (
        isoar.isoar_worker.check_module_has_function("elastic_siem", "irsoar_provide_new_alerts", mlog) == True
    ), "elastic_siem.irsoar_provide_new_alerts does not exist"
    assert (
        isoar.isoar_worker.check_module_has_function("elastic_siem", "some_invalid_function", mlog) == False
    ), "elastic_siem.some_invalid_function exists"
    assert (
        isoar.isoar_worker.check_module_has_function("some_invalid_module", "some_invalid_function", mlog) == False
    ), "some_invalid_module.some_invalid_function exists"


def test_alert_collector():
    """Tests the alert_collector function.

    Args:
        None

    Returns:
        None
    """
    config = isoar.config_helper.Config().cfg
    mlog = isoar.logging_helper.Log("isoar_test_core")

    try:
        isoar.isoar_alert_collector.main(config)
    except Exception as e:
        pytest.fail("The alert_collector function failed: {}".format(e))
