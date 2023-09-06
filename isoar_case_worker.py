# IRIS-SOAR
# Created by: Martin Offermann
# This module is the worker script that handles the main logic of the IRIS-SOAR project.
#
# The main logic is as follows:
#
# - Loop through every installed integration for getting new alert alerts
# - Loop through each of the alerts and check if any playbook is able to handle it
# - - If a playbook is able to handle the alert, it will be executed
# - - If all playbooks are executed, the next alert will be checked
# (Playbooks decide if a alert is a false positive or not and what action should be taken. A playbook can and should make use of the libraries and integrations provided by IRIS-SOAR.)
# - If no playbook is able to handle the alert, it will be logged and the next alert will be checked

import traceback
import json

from dfir_iris_client.session import ClientSession
from dfir_iris_client.alert import Alert

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import lib.class_helper as class_helper  # TODO: Implement class_helper.py
from lib.generic_helper import del_none_from_dict, dict_get

DEBUG_ADD_AUDIT_LOG_TO_IRIS_CASE = True  # Weither or not to add the audit log to theiris-casewhen the worker is finished


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
    mlog = logging_helper.Log("isoar_worker")

    if debug:
        mlog.set_level("DEBUG")
        mlog.debug("Debug mode enabled.")

    # Get every installed integration from config
    integrations = config["integrations"]  # TODO: Implement this in config_helper.py

    mlog.info("Started IRIS-SOAR worker script")
    mlog.info("Checking for new alerts...")
    alert_list = []
    case_file_history = []

    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(
        apikey=config["integrations"]["dfir-iris"]["api_key"],
        host=config["integrations"]["dfir-iris"]["url"],
        ssl_verify=False,
    )

    # Get all alert in DFIR-IRIS that are 'new' or 'pending'
    alert_obj = Alert(session)
    response = alert_obj.filter_alerts(alert_status_id=[2, 3])
    if not response.is_success:
        mlog.error("Failed to get alerts from DFIR-IRIS. Error: " + response.log_error())
        return
    else:
        mlog.info("Successfully got alerts from DFIR-IRIS.")
        # print(response.get_data())
        alerts = response.get_data_field("alerts")

        if not alerts:
            mlog.info("No new alerts found.")
            return

    for alert in alerts:
        # Transform each Alert dict to a Alert object
        if dict_get(alert, "alert_title") is None:
            mlog.error("Current alert seems malformed as it has no name. Skipping.")
            continue

        try:
            alert_title = alert["alert_title"]
            alert_id = alert["alert_id"]

            mlog.info(f"Transforming alert '{alert_title}' ({alert_id})) to a Alert object.")

            for integration in integrations:
                if integration == "dfir-iris":
                    continue
                if not check_module_exists(integration):
                    mlog.error("The integration " + integration + " does not exist. Skipping.")
                    continue
                if not check_module_has_function(integration, "irsoar_transform_alert_to_alert", mlog):
                    mlog.info(
                        "The integration "
                        + integration
                        + " does not have the function 'irsoar_transform_alert_to_alert'. Skipping."
                    )
                    continue
                integration_config = config["integrations"][integration]
                alert = getattr(__import__("integrations." + integration), integration).irsoar_transform_alert_to_alert(
                    integration_config, alert
                )
                if not isinstance(alert, class_helper.Alert):
                    mlog.error("The integration " + integration + " did not return a valid Alert object. Skipping.")
                    continue
                else:
                    mlog.info("The integration " + integration + " transformed the alert to a Alert object successfully.")
                    alert_list.append(alert)
        except Exception as e:
            mlog.error(f"Failed to transform alert {alert['alert_title']} to Alert object. Error: " + traceback.format_exc())
            continue

    mlog.info("Finished transforming alerts to Alert objects.")

    # Now we must ask each "alert_playbook" if it wants to create a new case for (one- / multiple of-) the alerts. The playbook has to return the list of case objects it created.
    mlog.info("Asking alert_playbooks if they want to create a new case for the alerts...")
    case_list = []
    for alert_playbook in config["alert_playbooks"]:
        # Check if the alert_playbook is enabled
        if not config["alert_playbooks"][alert_playbook]["enabled"]:
            mlog.warning("The alert_playbook " + alert_playbook + " is disabled. Skipping.")
            continue

        # Check if the alert_playbook exists
        if not check_module_exists(alert_playbook):
            mlog.error("The alert_playbook " + alert_playbook + " does not exist. Skipping.")
            continue

        # Check if the alert_playbook has the function 'irsoar_handle_alerts'
        if not check_module_has_function(alert_playbook, "irsoar_handle_alerts", mlog):
            mlog.info("The alert_playbook " + alert_playbook + " does not have the function 'irsoar_handle_alerts'. Skipping.")
            continue

        # Let the alert_playbook handle the alert
        try:
            mlog.info(f"Alert_playbook can handle the alerts. Calling it to handle.")
            module_import = __import__("alert_playbooks." + alert_playbook)
            alert_playbook_import = getattr(module_import, alert_playbook)
            case_list = alert_playbook_import.irsoar_handle_alerts(alert_list)
        except Exception as e:
            mlog.warning(
                "The alert_playbook " + alert_playbook + " failed to handle the alerts. Error: " + traceback.format_exc()
            )
            continue

    # Loop through each returned case and check if any case_playbook can handle it
    for case in case_list:
        alert_title = case.get_title()
        alert_id = case.uuid
        alertHandled = False

        # Check every playbook if it can handle the alert
        for playbook_name in config["playbooks"]:
            # Check if the playbook is enabled
            if not config["playbooks"][playbook_name]["enabled"]:
                mlog.warning("The playbook " + playbook_name + " is disabled. Skipping.")
                continue

            # Check if the playbook exists
            if not check_module_exists(playbook_name, playbook=True):
                mlog.error("The playbook " + playbook_name + " does not exist. Skipping.")
                continue

            # Ask the playbook if it can handle the alert
            try:
                mlog.info(
                    f"Calling playbook {playbook_name} to check if it can handle current alert '{alert_title}' ({str(alert_id)})"
                )
                module_import = __import__("playbooks." + playbook_name)
                playbook_import = getattr(module_import, playbook_name)
                can_handle = playbook_import.irsoar_can_handle_alert(case)
            except Exception as e:
                mlog.warning(
                    "The playbook "
                    + playbook_name
                    + " failed to check if it can handle the alert. Error: "
                    + traceback.format_exc()
                )
                continue

            # Let the playbook handle the alert
            if can_handle:
                try:
                    mlog.info(f"Playbook can handle the alert. Calling it to handle: '{alert_title}' ({str(alert_id)})")
                    case_file_new = playbook_import.irsoar_handle_alert(case)
                except Exception as e:
                    mlog.warning(
                        "The playbook " + playbook_name + " failed to handle the alert. Error: " + traceback.format_exc()
                    )
                    continue

                # Check if the playbook handled the alert correctly
                if not isinstance(case_file_new, class_helper.CaseFile):
                    mlog.error("The playbook " + playbook_name + " did not return a valid alert case. Skipping.")
                    continue
                else:
                    mlog.info("The playbook " + playbook_name + " handled the alert correctly.")
                    alertHandled = True

                # Add the alert case to the detectior case array
                mlog.info(f"Adding alert case for alert {alert_title} ({str(alert_id)}) to the alert case array.")
                case_file_new.playbooks.append(playbook_name)
                case_file_history.append(case_file_new)
            else:
                mlog.info(f"Playbook can not handle the alert. Skipping.")

        # If no playbook was able to handle the alert, log it
        if not alertHandled:
            mlog.warning("No playbook was able to handle the alert " + alert_title + " (" + str(alert_id) + ").")
        else:
            mlog.info("Alert " + alert_title + " (" + str(alert_id) + ") was handled successfully.")
            case: class_helper.CaseFile
            last_audit = class_helper.AuditLog(
                "ISOAR_WORKER",
                99,
                "Alert handled successfully.",
                "The alert was handled successfully by at least one playbook.",
            )
            case.update_audit(last_audit, mlog)

            if DEBUG_ADD_AUDIT_LOG_TO_IRIS_CASE:
                mlog.debug("Adding audit log to iris_case...")
                try:
                    trail_str = ""
                    for audit in case.audit_trail:
                        if audit.result_had_errors:
                            trail_str += "<p style='color:red'>"
                        elif audit.result_had_warnings:
                            trail_str += "<p style='color:orange'>"
                        else:
                            trail_str += "<p style='color:green'>"
                        trail_str += str(audit).replace("\n", "<br>") + "</p><br>"
                    # Add to iris-case
                    iris_case_number = case.get_iris_case_number()
                    if not iris_case_number:
                        mlog.warning("Could not add audit log toiris-casebecause noiris-casenumber was found.")
                        continue
                    iris_case = irsoar_add_note_to_iris_case(
                        iris_case_number,
                        "raw",
                        False,
                        "(DEBUG) Audit Log Trail",
                        trail_str,
                        visible_for_customer=False,
                        raw_body_type="text/html",
                    )
                    mlog.info("Added audit log toiris-case" + str(iris_case_number) + ".")
                except Exception as e:
                    mlog.error(
                        "Failed to add audit log toiris-case" + str(iris_case_number) + ". Error: " + traceback.format_exc()
                    )

    mlog.info("Finished worker script.")


if __name__ == "__main__":
    main(config_helper.Config().cfg)
    pass
