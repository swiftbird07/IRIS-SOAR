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
import logging

# For new detections:
from lib.class_helper import Rule, Detection

# For context for detections (remove unused types):
from lib.class_helper import DetectionReport, NetworkFlow, LogMessage, Process

import datetime
import requests
from elasticsearch import Elasticsearch
from ssl import create_default_context
from functools import reduce


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

    # Disable elasticsearch warnings (you can remove this if you want to see the warnings)
    es_log = logging.getLogger("elasticsearch")
    es_log.setLevel(logging.ERROR)
    return mlog


def deep_get(dictionary, keys, default=None):
    """Gets a value from a nested dictionary.

    Args:
        dictionary (dict): The dictionary to get the value from
        keys (str): The keys to get the value from
        default (any): The default value to return if the key does not exist

    Returns:
        any: The value of the key or the default value
    """
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, dict) else default,
        keys.split("."),
        dictionary,
    )


def acknowledge_alert(mlog, config, alert_id):
    """Acknowledges an alert in Elastic-SIEM.

    Args:
        mlog (logging_helper.Log): The logging object
        config (dict): The configuration dictionary for this integration
        alert_id (str): The ID of the alert to acknowledge

    Returns:
        None
    """
    mlog.debug("acknowledge_alert() called with alert_id: " + alert_id)

    elastic_host = config["elastic_url"]
    elastic_user = config["elastic_user"]
    elastic_pw = config["elastic_password"]

    indices = requests.get(
        elastic_host + "/_cat/indices/.internal.alerts-security.alerts-default-*?h=idx",
        auth=(elastic_user, elastic_pw),
        verify=False,
    )
    if indices.status_code != 200:
        mlog.warning(
            "Failed to acknowledged alert with id: "
            + alert_id
            + " -> Failed to get Kibana security indices. Got status code: "
            + str(indices.status_code)
            + " and response: "
            + indices.text
        )
        return False

    mlog.debug("found {} matching indices for acknowleding".format(len(indices.text.splitlines())))

    for index in indices.text.splitlines():
        mlog.debug("found Kibana security index: " + index)

        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        request_data = '{"doc": {"kibana.alert.workflow_status": "acknowledged"}}'
        posturl = elastic_host + "/" + index + "/_update/" + id

        response = requests.post(
            posturl,
            data=request_data,
            headers=headers,
            auth=(elastic_user, elastic_pw),
            verify=False,
        )
        if response.status_code == 200:
            mlog.dlog("got 200 response from Kibana.")
            response = response.json()

            if deep_get(response, "_shards.successful", False):
                mlog.info("Successfully acknowledged alert with id: " + alert_id)
                return True
            else:
                mlog.debug("couldn't acknowledge alert for index '" + index + "'\n" + response.text + ". Trying next index...")
        else:
            mlog.warning(
                "Failed to acknowledge alert with id: "
                + alert_id
                + ". Got status code: "
                + str(response.status_code)
                + " and response: "
                + response.text
            )
            return False
    mlog.warning("Failed to acknowledge alert with id: " + alert_id + " -> Tried all indices ({})".format(len(indices.text.splitlines())))


def zs_provide_new_detections(config, TEST=False) -> List[Detection]:
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
    detections = List[Detection]

    try:
        elastic_url = config["elastic_url"]
        elastic_user = config["elastic_user"]
        elastic_password = config["elastic_password"]
        elastic_verify_certs = config["elastic_verify_certs"]
    except KeyError as e:
        mlog.error("Missing config parameters: " + e)
        return detections

    requests.packages.urllib3.disable_warnings()

    # Dictionary structured like an Elasticsearch query:
    query_body = {"query": {"bool": {"must": {"match": {"kibana.alert.workflow_status": "open"}}}}}

    ssl_context = create_default_context()
    ssl_context.check_hostname = elastic_verify_certs

    elastic_client = Elasticsearch(
        hosts=[elastic_url],
        http_auth=(elastic_user, elastic_password),
        ssl_context=ssl_context,
        verify_certs=elastic_verify_certs,
    )

    # Call the client's search() method, and have it return results
    result = elastic_client.search(index=".internal.alerts-security.alerts-default-*", body=query_body, size=999)

    # See how many "hits" it returned using the len() function
    hits = result["hits"]["hits"]
    mlog.info("Found " + str(len(hits)) + " hits.")

    if len(hits) == 0:
        mlog.info("No new detections found.")
        return detections

    # Iterate the nested dictionaries inside the ["hits"]["hits"] list
    for num, doc in enumerate(hits):
        # print the document ID
        mlog.info("Document ID: {}".format(doc["_id"]))
        # print the document source
        mlog.info("Document source: {}".format(document_source))
        # print the document score
        mlog.info("Document score: {}".format(doc["_score"]))
        # print the document index
        mlog.info("Document index: {}".format(doc["_index"]))
        # print the document type
        mlog.info("Document type: {}".format(doc["_type"]))

        # Create a new detection object
        rule_list = []
        document_source = doc["_source"]
        rule_list.append(
            Rule(
                doc["_id"],
                document_source["kibana.alert.rule.name"],
                document_source["kibana.alert.rule.severity"],
                description=document_source["kibana.alert.rule.description"],
                tags=document_source["kibana.alert.rule.tags"],
                timestamp=document_source["kibana.alert.rule.timestamp"],
            )
        )
        detection = Detection(doc["_id"], document_source["kibana.alert.rule.name"], rule_list)
        mlog.info("Created detection: " + detection)
        detections.append(detection)

    try:
        acknowledge_alert(mlog, config, detection.id)
    except Exception as e:
        mlog.error("Failed to acknowledge alert with id: " + detection.id + ". Error: " + str(e))

    # ...
    # ...

    mlog.info("zs_provide_new_detections() found " + str(len(detections)) + " new detections.")
    mlog.debug("zs_provide_new_detections() found the following new detections: " + str(detections))
    return detections


def zs_provide_context_for_detections(
    config, detection_report: DetectionReport, required_type: type, TEST=False
) -> Union[NetworkFlow, LogMessage, Process]:
    """Returns a DetectionReport object with context for the detections from the XXX integration.

    Args:
        config (dict): The configuration dictionary for this integration
        detection (DetectionReport): The DetectionReport object to add context to
        required_type (type): The type of context to return. Can be one of the following:
            [ContextFlow, ContextLog]
        test (bool, optional): If set to True, dummy context data will be returned. Defaults to False.

    Returns:
        Union[ContextFlow, ContextLog]: The required context of type 'required_type'
    """
    mlog = init_logging(config)
    detection_report_str = "'" + detection_report.get_title() + "' (" + str(detection_report.uuid) + ")"
    mlog.info(f"zs_provide_context_for_detections() called with detection report: {detection_report_str} and required_type: {required_type}")

    provided_typed = []
    provided_typed.append(NetworkFlow)
    provided_typed.append(LogMessage)
    provided_typed.append(Process)

    if required_type not in provided_typed:
        mlog.error("The required type is not provided by this integration. '" + str(required_type) + "' is not in " + str(provided_typed))
        raise TypeError("The required type is not provided by this integration.")

    if TEST:  # When called from unit tests, return dummy data. Can be removed in production.
        mlog.info("Running in test mode. Returning dummy data.")
        return_objects = []
        if required_type == NetworkFlow:
            context_object = NetworkFlow(
                detection_report.uuid, datetime.datetime.now(), "Elastic-SIEM", "10.0.0.1", 123, "123.123.123.123", 80, "TCP"
            )
        elif required_type == Process:
            context_object = Process(detection_report.uuid, "test.exe", 123, process_start_time=datetime.datetime.now())
        elif required_type == LogMessage:
            context_object = LogMessage(detection_report.uuid, datetime.datetime.now(), "Some log message", "Elastic-SIEM")
        return_objects.append(context_object)
        detection_example = detection_report.detections[0]
        detection_name = detection_example.name
        detection_id = detection_example.id

    # ...
    # ...
    # ... Add code to return the required type here
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
                + str(detection_report)
            )
        else:
            mlog.info(
                "zs_provide_context_for_detections() found no context for detection: " + detection_name + " and required_type: " + str(required_type)
            )
    return return_objects
