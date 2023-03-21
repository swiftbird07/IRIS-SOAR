# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with Elastic-SIEM.
#
# This module is capable of:
# [X] Providing new detections.
# [X] Providing context for detections of type [ContextFlow | ContextProcess | ContextLog]
# ...from Elastic REST API inteface.
#
# Integration Version: 0.0.1

from typing import Union, List
import lib.logging_helper as logging_helper

# For new detections:
from lib.class_helper import Rule, Detection

# For context for detections (remove unused types):
from lib.class_helper import ContextFlow, ContextLog, ContextProcess

import datetime

LOG_LEVEL = "DEBUG"  # Force log level. Recommended to set to DEBUG during development.
# from elasticsearch import Elasticsearch


def main():
    pass


def init_logging(config):
    """Initializes the logging for this module.

    Args:
        config (dict): The configuration dictionary for this integration

    Returns:
        logging_helper.Log: The logging object
    """
    log_level_file = config["logging"]["log_level_file"]  # be aware that only configs from this integration are available not the general config
    log_level_stdout = config["logging"]["log_level_stdout"]
    log_level_syslog = config["logging"]["log_level_syslog"]

    mlog = logging_helper.Log(__name__, log_level_stdout=log_level_stdout, log_level_file=log_level_file)
    return mlog


def zs_provide_new_detections(config, TEST=False) -> list[Detection]:
    """Returns a list of new detections.

    Args:
        config (dict): The configuration dictionary for this integration
        test_return_dummy_data (bool, optional): If set to True, dummy data will be returned. Defaults to False.

    Returns:
        list[Detection]: A list of new detections
    """
    mlog = init_logging(config)
    mlog.info("zs_provide_new_detections() called.")

    detections = []

    if TEST:  # When called from unit tests, return dummy data. Can be removed in production.
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


def zs_provide_context_for_detections(
    config, detection: Detection, required_type: type, TEST=False
) -> Union[ContextFlow, ContextLog, ContextProcess]:
    """Returns a DetectionReport object with context for the detections from the XXX integration.

    Args:
        config (dict): The configuration dictionary for this integration
        detection (Detection): The Detection object to add context to
        required_type (type): The type of context to return. Can be one of the following:
            [ContextFlow, ContextLog]
        test (bool, optional): If set to True, dummy context data will be returned. Defaults to False.

    Returns:
        Union[ContextFlow, ContextLog]: The required context of type 'required_type'
    """
    mlog = init_logging(config)
    mlog.info("zs_provide_context_for_detections() called with detection: " + str(detection) + " and required_type: " + str(required_type))

    provided_typed = []
    provided_typed.append(ContextFlow)
    provided_typed.append(ContextLog)
    provided_typed.append(ContextProcess)

    if required_type not in provided_typed:
        mlog.error("The required type is not provided by this integration. '" + str(required_type) + "' is not in " + str(provided_typed))
        raise TypeError("The required type is not provided by this integration.")

    if TEST:  # When called from unit tests, return dummy data. Can be removed in production.
        mlog.info("Running in test mode. Returning dummy data.")
        if required_type == ContextFlow:
            return_object = ContextFlow(datetime.datetime.now(), "Elastic-SIEM", "10.0.0.1", 123, "123.123.123.123", 80, "TCP")
        elif required_type == ContextProcess:
            return_object = ContextProcess("test.exe", 123, process_start_time=datetime.datetime.now())
        elif required_type == ContextLog:
            return_object = ContextLog(datetime.datetime.now(), "Some log message", "Elastic-SIEM")

    # ...
    # ...
    # ... Add code to return the required type here
    # ...
    # ...

    if type(return_object) != required_type:  # Sanity check. 'return_object' is the object to be returned by above code.
        mlog.error("The returned object is not of the required type. Returning None.")
        return None
    if return_object != None:
        mlog.info("zs_provide_context_for_detections() found context for detection '" + detection.name + "' and required_type: " + str(required_type))
        mlog.debug("zs_provide_context_for_detections() returned the following context: " + str(return_object) + " for detection: " + str(detection))
    else:
        mlog.info(
            "zs_provide_context_for_detections() found no context for detection: " + str(detection) + " and required_type: " + str(required_type)
        )
    return return_object
