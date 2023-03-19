# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the zsoar.py module.
# It will test if the prvided arguments are working as expected.

import pytest
import zsoar


def test_logger():
    """Tests the logger helper function.

    Args:
        None

    Returns:
        None
    """
    try:
        mlog = zsoar.logging_helper.Log("zsoar_test_lib", log_level_stdout="INFO")
        mlog.info("Test message")
    except AttributeError as e:
        pytest.fail("The logger could not be initialized: {}".format(e))
    except Exception as e:
        pytest.fail("The logger could not be used: {}".format(e))


def test_config_loading():
    """Tests the config loading function and its validation.

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
    mlog = zsoar.logging_helper.Log("zsoar_test_lib")
    cfg["logging"]["log_level_file"] = "some_invalid_value"
    assert (
        zsoar.config_helper.check_config(cfg, mlog) == False
    ), "The config is valid, but should not be (Value test)."

    # Reset the config
    cfg["logging"]["log_level_file"] = "debug"
    assert (
        zsoar.config_helper.check_config(cfg, mlog) == True
    ), "The config is not valid after resetting."

    # Test if invalid types are detected
    cfg["logging"]["log_level_stdout"] = True
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
    tmp = cfg["logging"]["log_level_file"]

    cfg["logging"]["log_level_file"] = "some_invalid_value"
    assert (
        zsoar.config_helper.save_config(cfg) == False
    ), "Saving invalid config to file did not fail"

    cfg["logging"]["log_level_file"] = "debug"
    assert zsoar.config_helper.save_config(cfg) == True, "Saving valid new config to file failed"

    # Reset
    cfg["logging"]["log_level_file"] = tmp
    assert zsoar.config_helper.save_config(cfg) == True, "Saving valid old config to file failed"
