# Z-SOAR
# Created by: Martin Offermann
# This module is the worker script that handles the main logic of the Z-SOAR project.
#
# The main logic is as follows:
#
# - Loop through every installed integration for getting new detection alerts
# - Loop through each of the detections and check if any playbook is able to handle it
# - - If a playbook is able to handle the detection, it will be executed
# - - If all playbooks are executed, the next detection will be checked
# (Playbooks decide if a detection is a false positive or not and what action should be taken. A playbook can and should make use of the libraries and integrations provided by Z-SOAR.)
# - If no playbook is able to handle the detection, it will be logged and the next detection will be checked

import traceback

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import lib.class_helper as class_helper  # TODO: Implement class_helper.py
from integrations.znuny_otrs import zs_add_note_to_ticket


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
    """Main function of the worker script.

    Args:
        config (dict): The config dictionary
        fromDaemon (bool): If the script was called from the daemon

    Returns:
        None
    """
    # Get the logger
    mlog = logging_helper.Log("zsoar_worker")

    if debug:
        mlog.set_level("DEBUG")
        mlog.debug("Debug mode enabled.")

    # Get every installed integration from config
    integrations = config["integrations"]  # TODO: Implement this in config_helper.py

    mlog.info("Started Z-SOAR worker script")
    mlog.info("Checking for new detections...")
    DetectionList = []
    CaseFileList = []

    for integration in integrations:
        module_name = integration
        integration = integrations[integration]  # we want the whole dict not just the name to work with

        # Check if the module is enabled
        if not integration["enabled"]:
            mlog.warning("The module " + module_name + " is disabled. Skipping.")
            continue

        if module_name == "znuny_otrs" and integration["detection_provider"]["enabled"] == False:
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

                # For now every 'Detection' equals exactly one 'CaseFile' (this may change in the future to reduce duplicates, etc..)
                case_file_tmp = class_helper.CaseFile(detection)  # TODO: make this more advanced

                DetectionList.append(case_file_tmp)

    # Loop through each detection
    for case_file in DetectionList:
        detection_title = case_file.get_title()
        detection_id = case_file.uuid
        detectionHandled = False

        # Check every playbook if it can handle the detection
        for playbook_name in config["playbooks"]:
            # Check if the playbook is enabled
            if not config["playbooks"][playbook_name]["enabled"]:
                mlog.warning("The playbook " + playbook_name + " is disabled. Skipping.")
                continue

            # Check if the playbook exists
            if not check_module_exists(playbook_name, playbook=True):
                mlog.error("The playbook " + playbook_name + " does not exist. Skipping.")
                continue

            # Ask the playbook if it can handle the detection
            try:
                mlog.info(
                    f"Calling playbook {playbook_name} to check if it can handle current detection '{detection_title}' ({str(detection_id)})"
                )
                module_import = __import__("playbooks." + playbook_name)
                playbook_import = getattr(module_import, playbook_name)
                can_handle = playbook_import.zs_can_handle_detection(case_file)
            except Exception as e:
                mlog.warning(
                    "The playbook "
                    + playbook_name
                    + " failed to check if it can handle the detection. Error: "
                    + traceback.format_exc()
                )
                continue

            # Let the playbook handle the detection
            if can_handle:
                try:
                    mlog.info(
                        f"Playbook can handle the detection. Calling it to handle: '{detection_title}' ({str(detection_id)})"
                    )
                    case_file_new = playbook_import.zs_handle_detection(case_file)
                except Exception as e:
                    mlog.warning(
                        "The playbook " + playbook_name + " failed to handle the detection. Error: " + traceback.format_exc()
                    )
                    continue

                # Check if the playbook handled the detection correctly
                if not isinstance(case_file_new, class_helper.CaseFile):
                    mlog.error("The playbook " + playbook_name + " did not return a valid detection case. Skipping.")
                    continue
                else:
                    mlog.info("The playbook " + playbook_name + " handled the detection correctly.")
                    detectionHandled = True

                # Add the detection case to the detectior case array
                mlog.info(
                    f"Adding detection case for detection {detection_title} ({str(detection_id)}) to the detection case array."
                )
                CaseFileList.append(case_file_new)
            else:
                mlog.info(f"Playbook can not handle the detection. Skipping.")

        # If no playbook was able to handle the detection, log it
        if not detectionHandled:
            mlog.warning("No playbook was able to handle the detection " + detection_title + " (" + str(detection_id) + ").")
        else:
            mlog.info("Detection " + detection_title + " (" + str(detection_id) + ") was handled successfully.")

    mlog.info("Finished worker script.")


if __name__ == "__main__":
    main(config_helper.Config().cfg)
    pass
