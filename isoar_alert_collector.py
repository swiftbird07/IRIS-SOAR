# IRIS-SOAR
# Created by: Martin Offermann
# This module is the collector script that handles the main logic of the IRIS-SOAR project.
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

import lib.logging_helper as logging_helper
import lib.class_helper as class_helper  # TODO: Implement class_helper.py
from lib.generic_helper import dict_get, del_none_from_dict
import lib.config_helper as config_helper


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
    mlog.info("Checking for new alerts...")
    AlertList = []
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

        if module_name == "dfir-iris" and integration["alert_provider"]["enabled"] == False:
            mlog.warning("The module " + module_name + " has disabled the alert provider. Skipping.")
            continue

        # Check if the module exists
        if not check_module_exists(module_name):
            mlog.error("The module " + module_name + " does not exist. Skipping.")
            continue

        # Check if module provides getting new alerts
        if not check_module_has_function(module_name, "irsoar_provide_new_alerts", mlog):
            mlog.debug(
                "The module " + module_name + " does not provide the function irsoar_provide_new_alerts. Skipping Integration."
            )
            continue

        # Make the actual call to the integration
        try:
            mlog.info("Calling module " + module_name)
            module_import = __import__("integrations." + module_name)
            module_import = getattr(module_import, module_name)
            integration_config = config["integrations"][module_name]
            new_alerts = module_import.irsoar_provide_new_alerts(integration_config)
        except Exception as e:
            mlog.warning(
                "The module "
                + module_name
                + " had an unhandled error when trying to provide new alerts. Error: "
                + traceback.format_exc()
                + ". Skipping Integration."
            )
            continue

        # Check if the returned type is valid
        if type(new_alerts) is not list:
            mlog.warning("The module " + module_name + " provided invalid alert(s). Skipping Integration.")
            continue

        # Check if the module provided any alerts
        if not new_alerts or len(new_alerts) == 0:
            mlog.info("The module " + module_name + " did not provide any alerts.")
            continue
        else:
            mlog.info("The module " + module_name + " provided " + str(len(new_alerts)) + " new alerts.")

        for alert in new_alerts:
            if not isinstance(alert, class_helper.Alert):
                mlog.warning("The module " + module_name + " provided an invalid alert. Skipping.")
            else:
                mlog.info("Adding new alert " + alert.name + " (" + str(alert.uuid) + ") to the alert array.")

                AlertList.append(alert)

    # Loop through each alert
    for alert in AlertList:
        alert_title = alert.name
        alert_id = alert.uuid
        alertHandled = False

        mlog.info("Pushing alert " + alert_title + " (" + str(alert_id) + ") to IRIS as alert.")

        # Initiate a session with our API key and host. Session stays the same during all the script run.
        session = ClientSession(
            apikey=config["integrations"]["dfir-iris"]["api_key"],
            host=config["integrations"]["dfir-iris"]["url"],
            ssl_verify=False,
        )

        alert_context_dict = {}

        # Try to expand fill context dict fields:
        try:
            alert: Alert = alert
            file_dict = alert.file.__dict__() if alert.file else {}
            alert_context_dict = del_none_from_dict(file_dict)

            # Add the device
            device_dict = alert.device.__dict__() if alert.device else {}
            alert_context_dict |= del_none_from_dict(device_dict)

            # Add the flow
            flow_dict = alert.flow.__dict__() if alert.flow else {}
            alert_context_dict |= del_none_from_dict(flow_dict)

            # Add the log
            log_dict = alert.log.__dict__() if alert.log else {}
            alert_context_dict |= del_none_from_dict(log_dict)

            # Add the process
            process_dict = alert.process.__dict__() if alert.process else {}
            alert_context_dict |= del_none_from_dict(process_dict)

            # Add the threat_intel
            threat_intel_dict = alert.threat_intel.__dict__() if alert.threat_intel else {}
            alert_context_dict |= del_none_from_dict(threat_intel_dict)

            # Add the location
            location_dict = alert.location.__dict__() if alert.location else {}
            alert_context_dict |= del_none_from_dict(location_dict)

            # Add the user
            user_dict = alert.user.__dict__() if alert.user else {}
            alert_context_dict |= del_none_from_dict(user_dict)

            # Add the registry
            registry_dict = alert.registry.__dict__() if alert.registry else {}
            alert_context_dict |= del_none_from_dict(registry_dict)

            # Add the http
            http_dict = alert.flow.http.__dict__() if alert.flow and alert.flow.http else {}
            alert_context_dict |= del_none_from_dict(http_dict)

            # Add the dns
            dns_dict = alert.flow.dns.__dict__() if alert.flow and alert.flow.dns else {}
            alert_context_dict |= del_none_from_dict(dns_dict)

        except Exception as e:
            mlog.warning("format_results() - Error while trying to format alert_context: " + str(e))

        # Add the IOCs
        iocs = []
        if alert.indicators["ip"]:
            for ip in alert.indicators["ip"]:
                iocs.append({"ioc_type_id": 79, "ioc_value": str(ip), "ioc_tlp_id": 1})
        if alert.indicators["domain"]:
            for domain in alert.indicators["domain"]:
                iocs.append({"ioc_type_id": 20, "ioc_value": domain, "ioc_tlp_id": 1})
        if alert.indicators["url"]:
            for url in alert.indicators["url"]:
                iocs.append({"ioc_type_id": 141, "ioc_value": url, "ioc_tlp_id": 1})
        if alert.indicators["hash"]:
            for hash in alert.indicators["hash"]:
                iocs.append({"ioc_type_id": 90, "ioc_value": hash, "ioc_tlp_id": 1})
        if alert.indicators["email"]:
            for email in alert.indicators["email"]:
                iocs.append({"ioc_type_id": 22, "ioc_value": email, "ioc_tlp_id": 1})
        if alert.indicators["countries"]:
            for country in alert.indicators["countries"]:
                iocs.append({"ioc_type_id": 96, "ioc_value": country, "ioc_tlp_id": 1})
        if alert.indicators["registry"]:
            for registry in alert.indicators["registry"]:
                iocs.append({"ioc_type_id": 109, "ioc_value": registry, "ioc_tlp_id": 1})
        if alert.indicators["other"]:
            for other in alert.indicators["other"]:
                iocs.append({"ioc_type_id": 96, "ioc_value": other, "ioc_tlp_id": 1})

        alert_severity = 2  # TODO: Implement severity calculation

        # Craft asset_id:
        asset_id = 3

        if alert.device.type == "host":
            if alert.device.os_family == "windows":
                asset_id = 9
            elif alert.device.os_family == "linux":
                asset_id = 4
            elif alert.device.os_family == "macos":
                asset_id = 6
            elif alert.device.os_family == "ios":
                asset_id = 8
            elif alert.device.os_family == "android":
                asset_id = 7
        else:
            if alert.device.os_family == "windows":
                asset_id = 10
            elif alert.device.os_family == "linux":
                asset_id = 3

        # Craft the alert data
        alert_data = {
            "alert_title": alert_title,
            "alert_description": alert.description,
            "alert_source": alert.vendor_id.upper(),
            "alert_source_ref": str(alert.uuid),
            "alert_source_link": alert.url,
            "alert_source_content": alert.raw,
            "alert_severity_id": alert_severity,
            "alert_status_id": 2,  # new
            "alert_context": alert_context_dict,
            "alert_source_event_time": str(alert.timestamp),
            "alert_note": "This alert was collected by IRIS-SOAR.",
            "alert_tags": "IRIS-SOAR,Security",
            "alert_iocs": iocs,
            "alert_assets": [
                {
                    "asset_name": alert.device.name if alert.device.name else "Unknown",
                    "asset_type_id": asset_id,
                    "asset_description": alert.device.description if alert.device.description else None,
                    "asset_ip": str(alert.device.local_ip) if alert.device.local_ip else None,
                    "asset_tags": alert.device.tags if alert.device.tags else None,
                }
            ],
            "alert_customer_id": 1,
            "alert_classification_id": 1,
        }
        # Initialize the case instance with the session
        alert = Alert(session=session)
        response = alert.add_alert(alert_data)
        print(response)

    # Check if the alert was handled correctly

    mlog.info("Finished collector script.")


if __name__ == "__main__":
    main(config_helper.Config().cfg)
    pass
