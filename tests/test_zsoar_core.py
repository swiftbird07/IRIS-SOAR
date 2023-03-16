# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the zsoar.py module.
# It will test if the prvided arguments are working as expected.

from asyncio import sleep
import builtins
import sys
import os
import mock
import pytest
import subprocess as subp


def test_import():
    """Tests if the module can be imported.

    Args:
        None

    Returns:
        None
    """
    try:
        import zsoar
        from zsoar import logging_helper

        return
    except ImportError:
        pytest.fail("The module can not be imported.")


import zsoar


def test_arg_parsing():
    """Tests parsing of arguments.

    Args:
        None

    Returns:
        None
    """
    # Test if the parser can be initialized
    try:
        parser = zsoar.add_arguments()
    except Exception as e:
        pytest.fail("The parser can not be initialized: {}".format(e))

    # Test if the parser can be used
    try:
        sys.argv = ["--version"]
        parser.parse_args()
    except Exception as e:
        pytest.fail("The parser can not be used: {}".format(e))
    return


def test_logger():
    """Tests the logger helper function.

    Args:
        None

    Returns:
        None
    """
    try:
        mlog = zsoar.logging_helper.Log("zsoar_test_core", log_level_stdout="INFO")
        mlog.info("Test message")
    except AttributeError as e:
        pytest.fail("The logger could not be initialized: {}".format(e))
    except Exception as e:
        pytest.fail("The logger could not be used: {}".format(e))


def test_config_loading():
    """Tests the config loading function.

    Args:
        None

    Returns:
        None
    """
    try:
        configObj = zsoar.config_helper.Config()
        cfg = configObj.cfg
    except Exception as e:
        pytest.fail("The config could not be loaded: {}".format(e))

    try:
        daemon_enabled = cfg["daemon"]["enabled"]  # Sample config value
        if daemon_enabled in [True, False]:
            pass
        else:
            pytest.fail(
                f"The config was loaded, but is misconfigured: cfg['daemon']['enabled'] not True or False: {daemon_enabled}"
            )
    except Exception as e:
        pytest.fail(f"The config was loaded, but is empty: {cfg}. {e}")

    # Test that invalid values are detected
    mlog = zsoar.logging_helper.Log("zsoar_test_core")
    cfg["logging"]["log_level_to_file"] = "some_invalid_value"
    assert (
        zsoar.config_helper.check_config(cfg, mlog) == False
    ), "The config is valid, but should not be (Value test)."

    # Reset the config
    cfg["logging"]["log_level_to_file"] = "debug"
    assert (
        zsoar.config_helper.check_config(cfg, mlog) == True
    ), "The config is not valid after resetting."

    # Test if invalid types are detected
    cfg["logging"]["split_file_on_startup"] = "a string"
    assert (
        zsoar.config_helper.check_config(cfg, mlog) == False
    ), "The config is valid, but should not be (Type test)."


def test_config_saving():
    """Tests the config saving function.

    Args:
        None

    Returns:
        None
    """
    configObj = zsoar.config_helper.Config()
    cfg = configObj.cfg
    assert zsoar.config_helper.save_config(cfg) == True, "Saving current config to file failed"
    tmp = cfg["logging"]["log_level_to_file"]

    cfg["logging"]["log_level_to_file"] = "some_invalid_value"
    assert (
        zsoar.config_helper.save_config(cfg) == False
    ), "Saving invalid config to file did not fail"

    cfg["logging"]["log_level_to_file"] = "debug"
    assert zsoar.config_helper.save_config(cfg) == True, "Saving valid new config to file failed"

    # Reset
    cfg["logging"]["log_level_to_file"] = tmp
    assert zsoar.config_helper.save_config(cfg) == True, "Saving valid old config to file failed"


def test_setup():
    """Tests the setup function.

    Args:
        None

    Returns:
        None
    """
    cfg = zsoar.config_helper.Config().cfg
    tmp = cfg

    zsoar.config_helper.save_config(cfg)

    # Following sub-test doesnt work, because a wrong input is ignored and the input is asked again. Therefore the test would hang:

    # with mock.patch.object(builtins, "input", lambda: "19"):
    #     zsoar.setup(0)
    # cfg = zsoar.config_helper.Config().cfg
    # assert cfg["setup"]["setup_step"] == 0, "The setup step accepted an invalid input."

    # Test vaild input True/False:
    cfg["setup"]["setup_step"] = 1
    cfg["daemon"]["enabled"] = False
    zsoar.config_helper.save_config(cfg)

    with mock.patch.object(builtins, "input", lambda: "y"):
        zsoar.setup(1, continue_steps=False)
    cfg = zsoar.config_helper.Config().cfg
    assert (
        cfg["setup"]["setup_step"] == 2
    ), "The setup step didn't progress after valid input (bool)."
    assert cfg["daemon"]["enabled"] == True, "The setup step didn't save new value (bool)."

    # Test vaild input Integer
    cfg["setup"]["setup_step"] = 2
    cfg["daemon"]["interval"] = 1
    zsoar.config_helper.save_config(cfg)

    with mock.patch.object(builtins, "input", lambda: 12):
        zsoar.setup(2, continue_steps=False)
    cfg = zsoar.config_helper.Config().cfg
    assert cfg["daemon"]["interval"] == 12, "The setup step didn't save new value (int)."
    assert (
        cfg["setup"]["setup_step"] == 3
    ), "The setup step didn't progress after valid input (int)."

    # Reset to original config
    assert (
        zsoar.config_helper.save_config(tmp) == True
    ), "Resetting config to original failed (test_setup)."


def test_startup_daemon():
    """Tests the startup function for spawning a daemon.

    Args:
        None

    Returns:
        None
    """
    mlog = zsoar.logging_helper.Log("zsoar_test_core")
    zsoar.startup(mlog)
    daemons = subp.check_output(["pgrep", "-f", "python3 zsoar_daemon.py"]).split()
    assert (
        daemons != [],
        "The daemon was not started.",
    )  # Will fail at the moment, as the daemon is not implemented yet.
    assert len(daemons) == 1, "More than one daemon was started."
    assert daemons[0].isdigit(), "The daemon PID is not a number."


def test_stop():
    """Tests the stop function.

    Args:
        None

    Returns:
        None
    """
    mlog = zsoar.logging_helper.Log("zsoar_test_core")
    zsoar.startup(mlog)
    sleep(1)
    zsoar.stop(mlog)
    daemons = subp.check_output(["pgrep", "-f", "python3 zsoar_daemon.py"]).split()
    assert daemons == [], "The daemon was not stopped."
