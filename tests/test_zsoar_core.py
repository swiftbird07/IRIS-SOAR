# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the zsoar.py module.
# It will test if the prvided arguments are working as expected.

import sys
import os
import pytest


def test_import():
    """Tests if the module can be imported.

    Args:
        None

    Returns:
        None
    """
    try:
        import zsoar

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
        parser = zsoar.parse_arguments()
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
        mlog = zsoar.logging_helper.Log.get_logger("zsoar_test_core")
        mlog.info("Test message")
    except AttributeError as e:
        pytest.fail("The logger could not be initialized: {}".format(e))
    except Exception as e:
        pytest.fail("The logger could not be used: {}".format(e))


def test_startup():
    """Tests the startup function.

    Args:
        None

    Returns:
        None
    """
    mlog = zsoar.logging_helper.Log.get_logger("zsoar_test_core")
    zsoar.startup(mlog)
