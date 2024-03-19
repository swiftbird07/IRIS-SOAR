# Integration for IRIS-SOAR
# Created by: Martin Offermann
# This module is used to integrate IRIS-SOAR with Wazuh-Indexer.
#
# This module is capable of:
# [X] Providing new alerts.
# [ ] Providing context for alerts of type [ContextFlow | ContextProcess | ContextFile | ContextRegistry]
# [ ] User interactive setup.
#
# Integration Version: 0.1.0
# Currently limited to process related alerts and contexts.

import logging
from typing import Union, List
import datetime
import requests
from elasticsearch import Elasticsearch, AuthenticationException
from ssl import create_default_context
import sys
import uuid
import json
import ipaddress
import re
import random
import string
import time

import lib.logging_helper as logging_helper

# For new alerts:
from lib.class_helper import Rule, Alert, ContextProcess, ContextFlow, ContextAsset

# For context for alerts:
from lib.class_helper import (
    CaseFile,
    ContextFlow,
    ContextLog,
    ContextProcess,
    cast_to_ipaddress,
    Location,
    DNSQuery,
    ContextFile,
    Certificate,
    ContextRegistry,
)
from lib.generic_helper import dict_get, get_from_cache, add_to_cache


ELASTIC_MAX_RESULTS = 100  # Maximum number of results to return from Elastic-SIEM for a Context in one query
VERBOSE_DEBUG = False  # If set to True, the script will print additional debug information to stdout, including the full Elastic-SIEM response
MAX_SIZE_ELASTICSEARCH_SEARCH = 10000  # Maximum number of results to return from Elastic-SIEM in one query
MAX_CACHE_ENTITY_SIZE = 100000  # Max size (in chars) an entity can have to be cached
LOOKBACK_DAYS = 7  # Number of days to look back for search results


def main():
    # Check if argumemnt 'setup' was passed to the script
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        return Exception("Setup not implemented yet.")
        IRSOAR_INTegration_setup()
    elif len(sys.argv) > 1:
        print("Unknown argument: " + sys.argv[1])
        print("Usage: python3 " + sys.argv[0] + " --setup")
        sys.exit(1)




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
    log_level_syslog = config["logging"]["log_level_syslog"]

    mlog = logging_helper.Log(__name__, log_level_stdout=log_level_stdout, log_level_file=log_level_file)

    # Disable elasticsearch warnings (you can remove this if you want to see the warnings)
    es_log = logging.getLogger("elasticsearch")
    es_log.setLevel(logging.ERROR)
    return mlog







def create_alert_from_doc(mlog, doc):
    # Iterate the nested dictionaries inside the ["hits"]["hits"] list

    # print the document ID
    if dict_get(doc, "_id") is not None:
        mlog.debug("Document ID: {}".format(doc["_id"]))
        # print the document source
        mlog.debug("Document source: {}".format(doc["_source"]))
        # print the document score
        mlog.debug("Document score: {}".format(doc["_score"]))
        # print the document index
        mlog.debug("Document index: {}".format(doc["_index"]))

        # Create a new alert object
        rule_list = []
        doc_dict = doc["_source"]
    else:
        doc_dict = doc
    rule_list = []

    # Check if building block alert (kibana.alert.building_block_type: "default")
    doc_parameters = doc["_source"]["kibana.alert.rule.parameters"]
    if dict_get(doc_parameters, "building_block_type", False):
        mlog.info("Skipping building block alert.")
        return None

    rule_list.append(
        Rule(
            doc_dict["kibana.alert.rule.uuid"],
            doc_dict["kibana.alert.rule.name"],
            doc_dict["kibana.alert.severity"],
            description=doc_dict["kibana.alert.rule.description"],
            tags=doc_dict["kibana.alert.rule.tags"],
            known_false_positives=doc_dict["kibana.alert.rule.false_positives"],
            query=dict_get(doc_dict, "kibana.alert.rule.parameters.query"),
            mitre_references=dict_get(doc_dict, "kibana.alert.rule.parameters.threat.technique.referencee"),
            risk_score=doc_dict["kibana.alert.risk_score"],
        )
    )
    mlog.debug("Created rules: " + str(rule_list))

    # Get the most relevant IP address of the host
    host_ip = None
    global_ip = None

    host_ip, global_ip = get_host_ip_from_doc(doc_dict)

    mlog.debug("Decided host IP: " + str(host_ip))
    alert_id = doc_dict["kibana.alert.uuid"]

    # Most EDR alerts are process related so check if a ContextProcess context can be created
    process = None
    if dict_get(doc_dict, "process.entity_id") is not None:
        process = create_process_from_doc(mlog, doc_dict)

    flow = None
    if dict_get(doc_dict, "source.ip") is not None and dict_get(doc_dict, "destination.ip") is not None:
        flow = create_flow_from_doc(mlog, doc_dict, alert_id)

    file = None
    if dict_get(doc_dict, "file.path") is not None:
        file = create_file_from_doc(mlog, doc_dict, alert_id)

    registry = None
    if dict_get(doc_dict, "registry.path") is not None:
        registry = create_registry_from_doc(mlog, doc_dict, alert_id)

    device = None
    if dict_get(doc_dict, "host.hostname") is not None:
        device = ContextAsset(
            name=dict_get(doc_dict, "host.hostname"),
            local_ip=host_ip,
            global_ip=global_ip,
            ips=dict_get(doc_dict, "host.ip"),
            mac=dict_get(doc_dict, "host.mac"),
            os_family=dict_get(doc_dict, "ost.os.Ext.variant"),
            os=dict_get(doc_dict, "host.os.name"),
            kernel=dict_get(doc_dict, "host.os.kernel"),
            os_version=dict_get(doc_dict, "host.os.version"),
            in_scope=True,
        )

    # Create the alert object
    alert = Alert(
        "elastic_siem",
        doc_dict["kibana.alert.rule.name"],
        rule_list,
        doc_dict["@timestamp"],
        description=doc_dict["kibana.alert.rule.description"],
        tags=doc_dict["kibana.alert.rule.tags"],
        host_name=dict_get(doc_dict, "host.hostname"),
        host_ip=host_ip,
        process=process,
        flow=flow,
        file=file,
        registry=registry,
        uuid=alert_id,
        device=device,
        severity=doc_dict["kibana.alert.risk_score"],
        raw=doc_dict,
        highlighted_fields=dict_get(doc_parameters, "investigation_fields"),
    )
    mlog.info("Created alert: " + str(alert))
    return alert
    # Done with this alert





def acknowledge_alert(mlog, config, alert_id, index):
    return # TODO


############################################
#### irsoar_transform_alert_to_alert ####
############################################


def irsoar_transform_alert_to_alert(config, alert, alert_id) -> Alert:
    """Transforms an alert into a Alert object.

    Args:
        config (dict): The configuration dictionary for this integration
        alert (dict): The alert to transform

    Returns:
        Alert: The transformed alert
    """
    mlog = init_logging(config)
    mlog.info("irsoar_transform_alert_to_alert() called.")
    doc = alert["alert_source_content"]
    alert = create_alert_from_doc(mlog, doc)
    alert.uuid = alert_id
    return alert


############################################
#### irsoar_provide_new_alerts ####
############################################


def irsoar_provide_new_alerts(config, TEST="") -> List[Alert]:
    """Returns a list of new alerts.

    Args:
        config (dict): The configuration dictionary for this integration
        test_return_dummy_data (bool, optional): If set to True, dummy data will be returned. Defaults to False.

    Returns:
        List[Alert]: A list of new alerts
    """

    # TODO: Search for kibana.alert.group.id if it exists, as some elastic signals by itself dont provide any context

    mlog = init_logging(config)
    mlog.info("irsoar_provide_new_alerts() called.")

    alerts = []
    global ELASTIC_MAX_RESULTS

    if TEST == "OFFLINE":  # When called from offline tests, return dummy data. Can be removed in production.
        mlog.info("Running in offline-test mode. Returning dummy data.")
        rule = Rule("123", "Some Rule", 0)
        ruleList = []
        ruleList.append(rule)
        alert1 = Alert("456", "Some Alert", ruleList, datetime.datetime.now())
        alerts.append(alert1)
        alert2 = Alert("789", "Some Alert", ruleList, datetime.datetime.now())
        alerts.append(alert2)
        return alerts

    # ...
    # Begin main logic
    # ...
    alerts = []

    try:
        endpoint = config["url"]
        user = config["user"]
        password = config["password"]
        index = config["index"]
        fields = config["fields"]
        size = config["size"]
        cert = config["cert"]
        verify = config["verify"]
    except KeyError as e:
        mlog.critical("Missing config parameters: " + e)
        return alerts

    requests.packages.urllib3.disable_warnings()


    if user:
        es = Elasticsearch(
            endpoint,
            http_auth=(user, password),
            verify_certs=verify,
            timeout=30,
        )
    else:
        es = Elasticsearch(
            endpoint, ca_certs=cert, verify_certs=verify, timeout=30
        )

    info = {}
    hits = []
    devices = []
    query = { }  # CHANGEME TO AN USEFUL QUERY
    total = "eq"
    # query string to show kql search
    info["querystring"] = ""
    # populate logs
    mlog.info(f'Searching Wazuh-Indexer for: {query} contained within the field name {fields}')
    objects = []

    # Call to Elasticsearch
    res = es.search(
        size=size,
        index=index,
        body={
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "multi_match": {"query": query, "fields": fields}
            },
        },
    )

    hits = res["hits"]["total"]["value"]

    mlog.info("Found " + str(len(hits)) + " hits.")

    if len(hits) == 0:
        mlog.info("No new alerts found.")
        return alerts

    for num, doc in enumerate(hits):
        alert = create_alert_from_doc(mlog, doc) # THIS WILL FAIL
        if alert is not None:
            alerts.append(alert)

        try:
            index = doc["_index"]
            acknowledge_alert(mlog, config, alert.uuid, index) if alert else None
        except Exception as e:
            alerts.remove(alert)
            mlog.critical(
                f"[LOOP PROTECTION] Removed alert {alert.name} ({alert.uuid}) from list of new alerts, because the alert could not be acknowledged and a loop might occur! Error: {e}"
            )

    # ...
    # ...

    mlog.info("irsoar_provide_new_alerts() found " + str(len(alerts)) + " new alerts.")
    mlog.debug("irsoar_provide_new_alerts() found the following new alerts: " + str(alerts))
    return alerts


############################################
#### irsoar_provide_context_for_alerts ####
############################################

