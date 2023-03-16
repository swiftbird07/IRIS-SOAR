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
