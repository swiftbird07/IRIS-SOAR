# ## EXAMPLE TEMPLATE FOR INTEGRATIONS ##
# For this template we assume that the integration provides new detections and context for detections of type ContextFlow and ContextLog using e.g a SIEM.
# If your integration does not provide context for detections, remove the zs_provide_context_for_detections() function.
# If your integration does not provide new detections, remove the zs_provide_new_detections() function.
# If your integration does not provide context for detections of type ContextFlow, remove the ContextFlow import and the ContextFlow type hint from the zs_provide_context_for_detections() function.
# (same for ContextLog, ContextProcess)
# ## Copy below this line ##
#
#
# Integration for Z-SOAR
# Created by: YOUR NAME
# This module is used to integrate Z-SOAR with XXX.
#
# This module is capable of:
# [ ] Providing new detections.
# [ ] Providing context for detections of type [ContextFlow | ContextProcess | ContextLog | ContextThreatIntel | HTTP
#     | DNSQuery | ContextFile | ThreatIntelDetection | Certificate] <- Remove unused types.
# ...from XXX API inteface.
#
# Integration Version: x.x.x

from typing import Union, List
import lib.logging_helper as logging_helper

# For new detections:
from lib.class_helper import Rule, Detection

# For context for detections (remove unused types):
from lib.class_helper import CaseFile, ContextFlow, ContextLog

LOG_LEVEL = "DEBUG"  # Force log level. Recommended to set to DEBUG during development.
# from elasticsearch import Elasticsearch


def main():
    pass  # Module is not intended to be run as a standalone script.


def init_logging(config):
    """Initializes the logging for this module.

    Args:
        config (dict): The configuration dictionary for this integration

    Returns:
        logging_helper.Log: The logging object
    """
    log_level_file = config["logging"][
        "log_level_file"
    ]  # be aware that only configs from this integration are available not the general config
    log_level_stdout = config["logging"]["log_level_stdout"]
    log_level_syslog = config["logging"]["log_level_syslog"]  # TODO: Add syslog support

    mlog = logging_helper.Log("integrations." + __name__, log_level_stdout=log_level_stdout, log_level_file=log_level_file)
    return mlog


############################################
#### zs_provide_new_detections ####
############################################


def zs_provide_new_detections(config, test_return_dummy_data=False) -> List[Detection]:
    """Returns a list of new detections.

    Args:
        config (dict): The configuration dictionary for this integration
        test_return_dummy_data (bool, optional): If set to True, dummy data will be returned. Defaults to False.

    Returns:
        List[Detection]: A list of new detections
    """
    mlog = init_logging(config)
    mlog.info("zs_provide_new_detections() called.")

    detections = []

    if test_return_dummy_data:  # When called from unit tests, return dummy data. Can be removed in production.
        mlog.info("Running in test mode. Returning dummy data.")
        rule = Rule("123", "Some Rule", 0)
        ruleList = []
        ruleList.append(rule)
        detection1 = Detection("456", "Some Detection", ruleList)
        detections.append(detection1)
        detection2 = Detection("789", "Some Detection", ruleList)
        detections.append(detection2)

    # ...
    # ...
    # ... Add code to return the detections here
    # ...
    # ...

    mlog.info("zs_provide_new_detections() found " + str(len(detections)) + " new detections.")
    mlog.debug("zs_provide_new_detections() found the following new detections: " + str(detections))
    return detections


############################################
#### zs_provide_context_for_detections ####
############################################


def zs_provide_context_for_detections(config, case_file: CaseFile, required_type: type, test=False) -> list:
    """Returns a CaseFile object with context for the detections from the XXX integration.

    Args:
        config (dict): The configuration dictionary for this integration
        detection (CaseFile): The CaseFile object to add context to
        required_type (type): The type of context to return. Can be one of the following:
            [ContextFlow, ContextLog]
        test (bool, optional): If set to True, dummy context data will be returned. Defaults to False.

    Returns:
        list of [ContextFlow | ContextLog]: The required contexts of type 'required_type'
    """
    mlog = init_logging(config)
    case_file_str = "'" + case_file.get_title() + "' (" + str(case_file.uuid) + ")"
    mlog.info(
        f"zs_provide_context_for_detections() called with detection case: {case_file_str} and required_type: {required_type}"
    )

    provided_typed = []
    provided_typed.append(ContextFlow)
    provided_typed.append(ContextLog)

    if required_type not in provided_typed:
        mlog.error(
            "The required type is not provided by this integration. '" + str(required_type) + "' is not in " + str(provided_typed)
        )
        raise TypeError("The required type is not provided by this integration.")

    # ...
    # ...
    # ... Add code to return the required type objects here
    # ...
    # ...

    for context_object in return_objects:
        if context_object != None:
            if type(context_object) != required_type:  # Sanity check that the 'return_object' has the required type
                mlog.error("The returned object is not of the required type. Returning None.")
                return None
            mlog.info(
                f"zs_provide_context_for_detections() found context for detection '{detection_name}' ({detection_id}) and required_type: {required_type}"
            )
            mlog.debug(
                "zs_provide_context_for_detections() returned the following context: "
                + str(context_object)
                + " for detection: "
                + str(case_file)
            )
        else:
            mlog.info(
                "zs_provide_context_for_detections() found no context for detection: "
                + detection_name
                + " and required_type: "
                + str(required_type)
            )
    return return_objects
