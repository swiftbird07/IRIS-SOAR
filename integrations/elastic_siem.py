# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with Elastic-SIEM.
#
# This module is capable of:
# [X] Providing new detections.
# [X] Providing context for detections of type [ContextFlow | ContextProcess | ContextLog]
# ...from Elastic REST API inteface.
#
# Integration Version: 0.0.2
# Currently limited to process related detections and contexts.

import logging
from typing import Union, List
import datetime
import requests
from elasticsearch import Elasticsearch, AuthenticationException
from ssl import create_default_context
from functools import reduce
import sys
import uuid

import lib.logging_helper as logging_helper

# For new detections:
from lib.class_helper import Rule, Detection, Process, NetworkFlow

# For context for detections (remove unused types):
from lib.class_helper import DetectionReport, NetworkFlow, LogMessage, Process, cast_to_ipaddress


LOG_LEVEL = "DEBUG"  # Force log level. Recommended to set to DEBUG during development.
ELASTIC_MAX_RESULTS = 50  # Maximum number of results to return from Elastic-SIEM in one query


def main():
    # Check if argumemnt 'setup' was passed to the script
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        zs_integration_setup()
    elif len(sys.argv) > 1:
        print("Unknown argument: " + sys.argv[1])
        print("Usage: python3 " + sys.argv[0] + " --setup")
        sys.exit(1)


def zs_integration_setup():
    # Import here because this is only needed for setup
    from lib.config_helper import setup_integration as set_int
    from lib.config_helper import setup_ask
    import tests.integrations.test_elastic_siem as test_elastic_siem

    intgr = "elastic_siem"

    print("This script will setup the integration 'Elastic SIEM' for Z-SOAR.")
    print("Please enter the required information below.")
    print("")

    set_int(intgr, "elastic_url", "url", "Enter the Elastic-SIEM URL", additional_info="Example: https://elastic-siem.example.com")

    set_int(
        intgr,
        "elastic_user",
        "str",
        "Enter the Elastic-SIEM username",
        additional_info="Be aware that this user needs at least the cluster roles: 'monitor', 'read_ccr' and all access to Kibana 'Security'",
    )

    set_int(intgr, "elastic_password", "secret", "Enter the Elastic-SIEM password for the user")

    set_int(
        intgr,
        "elastic_verify_certs",
        "y/n",
        "Verify Elastic-SIEM certificates?",
        additional_info="If set to 'n', the connection will be insecure, but you can use self-signed certificates.",
    )

    set_int(intgr, "logging", "log_level", "Enter the log level to stdout", sub_config="log_level_stdout")

    set_int(intgr, "logging", "log_level", "Enter the log level to file", sub_config="log_level_file")

    set_int(intgr, "logging", "log_level", "Enter the log level to syslog", sub_config="log_level_syslog")

    print("")
    print("")
    print("Do you want to test the integration before enabling it?")
    test_now = setup_ask("y", available_responses_list=["y", "n"])
    if test_now == "y":
        print("Testing the integration...")
        result = test_elastic_siem.test_zs_provide_new_detections()
        if result:
            print("Test successful!")
        else:
            print("Test failed!")
            print("Please check the log file for more information.")
            print("Please fix the issue and try again.")
            print("NOTICE: Not enabling the integration because the test failed.")
            sys.exit(1)

    set_int(intgr, "enabled", "y/n", message="Enable the integration now?")

    print("")
    print("Setup finished.")
    print("You can now use the integration in Z-SOAR!")


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


def create_flow_from_doc(mlog, doc_id, doc_dict):
    # Create flow object if applicable
    if "source.ip" in doc_dict and "destination.ip" in doc_dict:
        flow = NetworkFlow(
            datetime.datetime.now(),
            doc_dict["kibana.alert.uuid"],
            cast_to_ipaddress(doc_dict["source.ip"]),
            cast_to_ipaddress(doc_dict["destination.ip"]),
            doc_dict["source.port"],
            doc_dict["destination.port"],
            doc_dict["network.transport"],
            doc_dict["network.protocol"],
            doc_dict["network.bytes"],
            doc_dict["network.packets"],
            doc_dict["network.community_id"],
            doc_dict["network.direction"],
            doc_dict["network.type"],
            doc_dict["network.application"],
            doc_dict["network.bytes_out"],
            doc_dict["network.bytes_in"],
            doc_dict["network.packets_out"],
            doc_dict["network.packets_in"],
            doc_dict["network.packets_total"],
            doc_dict["network.bytes_total"],
        )
    else:
        flow = None

    mlog.debug("Created flow: " + str(flow))
    return flow


def create_process_from_doc(mlog, doc_id, doc_dict):
    """Creates a Process object from a Elastic-SIEM document."""
    mlog.debug("Creating Process object from Elastic-SIEM document for detection: " + doc_dict["kibana.alert.uuid"] + " and document: " + doc_id)

    dns = None  # TODO: Implement create_dns_from_doc
    files = None  # TODO: Implement create_file_from_doc
    flow = None  # TODO: Implement create_flow_from_doc
    http = None  # TODO: Implement create_http_from_doc

    created_files = []
    deleted_files = []
    modified_files = []

    # Get parent process entity to create a minimal process to link the current process to it
    parent_uuid = deep_get(doc_dict, "process.parent.entity_id")
    if parent_uuid is not None:
        parent = Process(parent_uuid, datetime.datetime.now(), doc_dict["kibana.alert.uuid"])
    else:
        parent = None

    children = []

    process = Process(
        timestamp=datetime.datetime.now(),
        related_detection_uuid=deep_get(doc_dict, "kibana.alert.uuid"),
        process_name=deep_get(doc_dict, "process.name"),
        process_id=deep_get(doc_dict, "process.pid"),
        parent_process_name=deep_get(doc_dict, "process.parent.name"),
        parent_process_id=deep_get(doc_dict, "process.parent.pid"),
        parent_process_arguments=deep_get(doc_dict, "process.parent.args"),
        process_path=deep_get(doc_dict, "process.executable"),
        process_md5=deep_get(doc_dict, "process.hash.md5"),
        process_sha1=deep_get(doc_dict, "process.hash.sha1"),
        process_sha256=deep_get(doc_dict, "process.hash.sha256"),
        process_command_line=deep_get(doc_dict, "process.args"),
        process_username=deep_get(doc_dict, "user.name"),
        process_owner=deep_get(doc_dict, "user.name"),
        process_start_time=deep_get(doc_dict, "process.start"),
        process_parent_start_time=deep_get(doc_dict, "process.parent.start"),
        process_current_directory=deep_get(doc_dict, "process.working_directory"),
        process_dns=dns,
        process_http=http,
        process_flow=flow,
        process_parent=parent,
        process_children=children,
        process_arguments=deep_get(doc_dict, "process.args"),
        created_files=created_files,
        deleted_files=deleted_files,
        modified_files=modified_files,
        process_uuid=deep_get(doc_dict, "process.entity_id"),
        is_complete=True,
    )

    mlog.debug("Created process: " + str(process))
    return process


def acknowledge_alert(mlog, config, alert_id, index):
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

    mlog.debug("Using Kibana security index: " + str(index))

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    request_data = '{"doc": {"kibana.alert.workflow_status": "acknowledged"}}'
    posturl = elastic_host + "/" + index + "/_update/" + alert_id

    response = requests.post(
        posturl,
        data=request_data,
        headers=headers,
        auth=(elastic_user, elastic_pw),
        verify=False,
    )
    if response.status_code == 200:
        mlog.debug("got 200 response from Kibana.")
        response = response.json()

        if deep_get(response, "_shards.successful", False):
            mlog.info("Successfully acknowledged alert with id: " + alert_id)
            return True
        elif deep_get(response, "_shards.failed", False):
            mlog.debug("Failed to acknowledge alert for index '" + index + "':" + response.text)
            return False
        else:
            mlog.warning("Tried to acknowledge alert for index '" + index + "' but it already was acknowledged.")
            return True
    else:
        mlog.warning(
            "Failed to acknowledge alert with id: " + alert_id + ". Got status code: " + str(response.status_code) + " and response: " + response.text
        )
        return False


############################################
#### zs_provide_new_detections ####
############################################


def zs_provide_new_detections(config, TEST="") -> List[Detection]:
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
    global ELASTIC_MAX_RESULTS

    if TEST == "OFFLINE":  # When called from offline tests, return dummy data. Can be removed in production.
        mlog.info("Running in offline-test mode. Returning dummy data.")
        rule = Rule("123", "Some Rule", 0)
        ruleList = []
        ruleList.append(rule)
        detection1 = Detection("456", "Some Detection", ruleList, datetime.datetime.now())
        detections.append(detection1)
        detection2 = Detection("789", "Some Detection", ruleList, datetime.datetime.now())
        detections.append(detection2)
        return detections

    # ...
    # Begin main logic
    # ...
    detections = []

    try:
        elastic_url = config["elastic_url"]
        elastic_user = config["elastic_user"]
        elastic_password = config["elastic_password"]
        elastic_verify_certs = config["elastic_verify_certs"]
    except KeyError as e:
        mlog.critical("Missing config parameters: " + e)
        return detections

    requests.packages.urllib3.disable_warnings()

    # Dictionary structured like an Elasticsearch query:
    query_body = {"query": {"bool": {"must": {"match": {"kibana.alert.workflow_status": "open"}}}}}

    # When called from online tests, search for acknowledged alerts instead, to guarentee results and not interfere with the real system.
    if TEST == "ONLINE":
        mlog.debug("Running in online-test mode. Searching for acknowledged alerts.")
        query_body = {"query": {"bool": {"must": {"match": {"kibana.alert.workflow_status": "acknowledged"}}}}}
        ELASTIC_MAX_RESULTS = 2  # Limit the number of results to 2, to make testing faster

    # Create an Elasticsearch client
    ssl_context = create_default_context()
    ssl_context.check_hostname = elastic_verify_certs

    elastic_client = Elasticsearch(
        hosts=[elastic_url],
        http_auth=(elastic_user, elastic_password),
        ssl_context=ssl_context,
        verify_certs=elastic_verify_certs,
    )

    # Call the client's search() method, and have it return results
    try:
        result = elastic_client.search(index=".internal.alerts-security.alerts-default-*", body=query_body, size=ELASTIC_MAX_RESULTS)
    except AuthenticationException:
        mlog.critical("Elasticsearch authentication with user '" + elastic_user + "' failed. Check your config. Aborting.")
        return detections
    except ConnectionError as e:
        mlog.critical("Elasticsearch connection failed with error: " + e + ". Aborting.")
        return detections

    # See how many "hits" it returned using the len() function
    hits = result["hits"]["hits"]
    mlog.info("Found " + str(len(hits)) + " hits.")

    if len(hits) == 0:
        mlog.info("No new detections found.")
        return detections

    # Iterate the nested dictionaries inside the ["hits"]["hits"] list
    for num, doc in enumerate(hits):
        # print the document ID
        mlog.debug("Document ID: {}".format(doc["_id"]))
        # print the document source
        mlog.debug("Document source: {}".format(doc["_source"]))
        # print the document score
        mlog.debug("Document score: {}".format(doc["_score"]))
        # print the document index
        mlog.debug("Document index: {}".format(doc["_index"]))

        # Create a new detection object
        rule_list = []
        doc_dict = doc["_source"]
        rule_list.append(
            Rule(
                doc_dict["kibana.alert.rule.uuid"],
                doc_dict["kibana.alert.rule.name"],
                doc_dict["kibana.alert.rule.severity"],
                description=doc_dict["kibana.alert.rule.description"],
                tags=doc_dict["kibana.alert.rule.tags"],
            )
        )
        mlog.debug("Created rules: " + str(rule_list))

        # Get the most relevant IP address of the host
        host_ip = None
        for ip in doc_dict["host"]["ip"]:
            ip_casted = cast_to_ipaddress(ip)
            if ip_casted is not None and ip_casted.is_private:
                if ip.startswith("10."):
                    host_ip = ip_casted
                    break
                elif ip.startswith("192.168."):
                    host_ip = ip_casted
        mlog.debug("Decided host IP: " + str(host_ip))

        # Most EDR detections are process related so check if a Process context can be created
        process = None
        if deep_get(doc_dict, "process.entity_id") is not None:
            process = create_process_from_doc(mlog, doc["_id"], doc_dict)

        # Create the detection object
        detection = Detection(
            doc_dict["kibana.alert.uuid"],
            doc_dict["kibana.alert.rule.name"],
            rule_list,
            doc_dict["@timestamp"],
            description=doc_dict["kibana.alert.rule.description"],
            tags=doc_dict["kibana.alert.rule.tags"],
            source=doc_dict["host"]["hostname"],
            process=process,
        )
        mlog.info("Created detection: " + str(detection))
        detections.append(detection)
        # Done with this detection

    try:
        index = doc["_index"]
        acknowledge_alert(mlog, config, detection.vendor_id, index)
    except Exception as e:
        mlog.error("Failed to acknowledge alert with id: " + detection.vendor_id + ". Error: " + str(e))

    # ...
    # ...

    mlog.info("zs_provide_new_detections() found " + str(len(detections)) + " new detections.")
    mlog.debug("zs_provide_new_detections() found the following new detections: " + str(detections))
    return detections


############################################
#### zs_provide_context_for_detections ####
############################################


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
            context_object = Process(
                uuid.uuid4(), datetime.datetime.now(), detection_report.uuid, "test.exe", 123, process_start_time=datetime.datetime.now()
            )
        elif required_type == LogMessage:
            context_object = LogMessage(detection_report.uuid, datetime.datetime.now(), "Some log message", "Elastic-SIEM", log_source_ip="10.0.0.3")
        return_objects.append(context_object)
        detection_example = detection_report.detections[0]
        detection_name = detection_example.name
        detection_id = detection_example.vendor_id

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


if __name__ == "__main__":
    # This integration should not be called directly besides running the integration setup!
    main()
