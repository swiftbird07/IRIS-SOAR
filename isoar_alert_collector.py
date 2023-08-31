# IRIS-SOAR
# Created by: Martin Offermann
# This module is the collector script that handles the main logic of the IRIS-SOAR project.
#
# The main logic is as follows:
#
# - Loop through every installed integration for getting new detection alerts
# - Loop through each of the detections and check if any playbook is able to handle it
# - - If a playbook is able to handle the detection, it will be executed
# - - If all playbooks are executed, the next detection will be checked
# (Playbooks decide if a detection is a false positive or not and what action should be taken. A playbook can and should make use of the libraries and integrations provided by IRIS-SOAR.)
# - If no playbook is able to handle the detection, it will be logged and the next detection will be checked

import traceback
import json
import dfir_iris_client

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import lib.class_helper as class_helper  # TODO: Implement class_helper.py
from lib.generic_helper import del_none_from_dict


def check_module_exists(module_name, playbook=False):
    """Checks if a module exists.

    Args:
        module_name (str): The name of the module

    Returns:
        bool: True if the module exists, False if not
    """
    try:
        if not playbook:
            __import__("integrations." + module_name)
        else:
            __import__("playbooks." + module_name)
        return True
    except ModuleNotFoundError:
        return False
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
    except ModuleNotFoundError:
        mlog.debug("ModuleNotFoundError: " + module_name + " does not exist.")
        return False


def main(config, fromDaemon=False, debug=False):
    """Main function of the collector script.

    Args:
        config (dict): The config dictionary
        fromDaemon (bool): If the script was called from the daemon

    Returns:
        None
    """
    # Get the logger
    mlog = logging_helper.Log("isoar_collector")

    if debug:
        mlog.set_level("DEBUG")
        mlog.debug("Debug mode enabled.")

    # Get every installed integration from config
    integrations = config["integrations"]  # TODO: Implement this in config_helper.py

    mlog.info("Started IRIS-SOAR collector script")
    mlog.info("Checking for new detections...")
    DetectionList = []
    alertFileHistory = []

    for integration in integrations:
        module_name = integration
        integration = integrations[integration]  # we want the whole dict not just the name to work with

        # Skif IRIS itself:
        if module_name == "dfir-iris":
            continue

        # Check if the module is enabled
        if not integration["enabled"]:
            mlog.warning("The module " + module_name + " is disabled. Skipping.")
            continue

        if module_name == "dfir-iris" and integration["detection_provider"]["enabled"] == False:
            mlog.warning("The module " + module_name + " has disabled the detection provider. Skipping.")
            continue

        # Check if the module exists
        if not check_module_exists(module_name):
            mlog.error("The module " + module_name + " does not exist. Skipping.")
            continue

        # Check if module provides getting new detections
        if not check_module_has_function(module_name, "zs_provide_new_detections", mlog):
            mlog.debug(
                "The module " + module_name + " does not provide the function zs_provide_new_detections. Skipping Integration."
            )
            continue

        # Make the actual call to the integration
        try:
            mlog.info("Calling module " + module_name)
            module_import = __import__("integrations." + module_name)
            module_import = getattr(module_import, module_name)
            integration_config = config["integrations"][module_name]
            new_detections = module_import.zs_provide_new_detections(integration_config)
        except Exception as e:
            mlog.warning(
                "The module "
                + module_name
                + " had an unhandled error when trying to provide new detections. Error: "
                + traceback.format_exc()
                + ". Skipping Integration."
            )
            continue

        # Check if the returned type is valid
        if type(new_detections) is not list:
            mlog.warning("The module " + module_name + " provided invalid detection(s). Skipping Integration.")
            continue

        # Check if the module provided any detections
        if not new_detections or len(new_detections) == 0:
            mlog.info("The module " + module_name + " did not provide any detections.")
            continue
        else:
            mlog.info("The module " + module_name + " provided " + str(len(new_detections)) + " new detections.")

        for detection in new_detections:
            if not isinstance(detection, class_helper.Detection):
                mlog.warning("The module " + module_name + " provided an invalid detection. Skipping.")
            else:
                mlog.info("Adding new detection " + detection.name + " (" + str(detection.uuid) + ") to the detection array.")

                DetectionList.append(detection)

    # Loop through each detection
    for detection_alert in DetectionList:
        detection_title = detection_alert.name
        detection_id = detection_alert.uuid
        detectionHandled = False

        mlog.info("Pushing detection " + detection_title + " (" + str(detection_id) + ") to IRIS as alert.")
        dfir_iris_client.case.create_alert(detection_alert)

    # Check if the alert was handled correctly

    mlog.info("Finished collector script.")


if __name__ == "__main__":
    main(config_helper.Config().cfg)
    pass
