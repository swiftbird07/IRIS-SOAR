# Z-SOAR
# Created by: Martin Offermann
# This module is a helper module that privides important classes and functions for the Z-SOAR project.

import os
import sys
import time

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper

# TODO: Implement all classes and functions used by zsoar_worker.py and its modules


class Detection:
    """Detection class. This class is used for storing detections."""

    def __init__(self):
        """Initializes a new Detection object."""
        self.id = None
        self.name = None
        self.description = None
        self.timestamp = None
        self.source = None
        self.source_ip = None
        self.source_port = None
        self.destination = None
        self.destination_ip = None
        self.destination_port = None
        self.protocol = None
        self.severity = None
        self.tags = None
        self.raw = None
        self.rules = None

    def __str__(self):
        """Returns the string representation of the object."""
        return (
            "Detection: "
            + self.name
            + " ("
            + self.id
            + ") from "
            + self.source
            + " ("
            + self.source_ip
            + ":"
            + self.source_port
            + ") to "
            + self.destination
            + " ("
            + self.destination_ip
            + ":"
            + self.destination_port
            + ") with protocol "
            + self.protocol
            + " and severity "
            + self.severity
        )

    # Getter and setter;

    # ...


class DetectionReport:
    """DetectionReport class. This class is used for storing detection reports. It extends the Detection class."""

    def __init__(self):
        """Initializes a new DetectionReport object."""
        self.detection = None
        self.playbook = None
        self.action = None
        self.action_result = None
        self.action_result_message = None
        self.action_result_data = None
        self.action_result_data_type = None
        self.action_result_data_raw = None
        self.action_result_data_raw_type = None
        self.action_result_data_raw_data = None
        self.action_result_data_raw_data_type = None
        self.action_result_data_raw_data_raw = None

    def __str__(self):
        """Returns the string representation of the object."""
        return (
            "DetectionReport: "
            + self.detection.name
            + " ("
            + self.detection.id
            + ") from "
            + self.detection.source
            + " ("
            + self.detection.source_ip
            + ":"
            + self.detection.source_port
            + ") to "
            + self.detection.destination
            + " ("
            + self.detection.destination_ip
            + ":"
            + self.detection.destination_port
            + ") with protocol "
            + self.detection.protocol
            + " and severity "
            + self.detection.severity
            + " was handled by playbook "
            + self.playbook
            + " with action "
            + self.action
            + " and result "
            + self.action_result
            + " ("
            + self.action_result_message
            + ")"
        )

    # Getter and setter;

    # ...


def check_module_exists(module_name):
    """Checks if a module exists.

    Args:
        module_name (str): The name of the module

    Returns:
        bool: True if the module exists, False if not
    """
    try:
        __import__("integrations." + module_name)
        return True
    except ImportError:
        return False


def check_module_has_function(module_name, function_name, mlog):
    """Checks if a module has a function.

    Args:
        module_name (str): The name of the module
        function_name (str): The name of the function

    Returns:
        bool: True if the module has the function, False if not
    """
    try:
        module = __import__("integrations." + module_name)
        integration = getattr(module, module_name)
        getattr(integration, function_name)
        return True
    except AttributeError as e:
        mlog.debug("AttributeError: " + str(e))
        return False


def main():
    pass


if __name__ == "__main__":
    main()
