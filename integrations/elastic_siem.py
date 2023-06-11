# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with Elastic-SIEM.
#
# This module is capable of:
# [X] Providing new detections.
# [X] Providing context for detections of type [ContextFlow | ContextProcess | ContextFile | ContextRegistry]
# [X] User interactive setup.
#
# Integration Version: 0.1.0
# Currently limited to process related detections and contexts.

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

import lib.logging_helper as logging_helper

# For new detections:
from lib.class_helper import Rule, Detection, ContextProcess, ContextFlow

# For context for detections:
from lib.class_helper import DetectionReport, ContextFlow, ContextLog, ContextProcess, cast_to_ipaddress, Location, DNSQuery, ContextFile, Certificate, ContextRegistry
from lib.generic_helper import dict_get, get_from_cache, add_to_cache


ELASTIC_MAX_RESULTS = 50  # Maximum number of results to return from Elastic-SIEM for a Context in one query
VERBOSE_DEBUG = False  # If set to True, the script will print additional debug information to stdout, including the full Elastic-SIEM response
MAX_SIZE_ELASTICSEARCH_SEARCH = 10000  # Maximum number of results to return from Elastic-SIEM in one query
LOOKBACK_DAYS = 7  # Number of days to look back for search results

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


def create_flow_from_doc(mlog, doc_id, doc_dict, detection_id):
    """Creates a ContextFlow object from an Elastic-SIEM document.
       Will also add DNS or HTTP objects to flow if available.

    Args:
        mlog (logging_helper.Log): The logging object
        doc_id (str): The Elastic-SIEM document ID
        doc_dict (dict): The Elastic-SIEM document as a dictionary
        detection_id (str): The detection ID
    
    Returns:
        ContextFlow: The ContextFlow object
    """
    src_location = None
    dst_location = None

    # Create flow object if applicable
    if "source" in doc_dict and "address" in doc_dict["source"]:
        src_ip = cast_to_ipaddress(dict_get(doc_dict, "source.address"))

        # Get source location if possible
        if "geo" in doc_dict["source"]:
            try:
                long_lat = doc_dict["source"]["geo"]["location"]
                src_location = Location(dict_get(doc_dict, "source.geo.country_name"), dict_get(doc_dict, "source.geo.city_name"), long_lat["lat"], long_lat["lon"], asn=dict_get(doc_dict, "source.as.number"), org=dict_get(doc_dict, "source.as.organization.name"), certainty=80)
            except Exception as e:
                mlog.warning("create_flow_from_doc - Could not parse source flow location from Elastic-SIEM document: " + str(e))
    else:
        src_ip = cast_to_ipaddress(dict_get(doc_dict, "host.ip")[0])
        mlog.warning("create_flow_from_doc - No source IP found in Elastic-SIEM document. Using host's IP: " + str(src_ip))
    
    if "destination" in doc_dict and "address" in doc_dict["destination"]:
        dst_ip = cast_to_ipaddress(dict_get(doc_dict, "destination.address"))

        # Get destination location if possible
        if "geo" in doc_dict["destination"]:
            try:
                long_lat = doc_dict["destination"]["geo"]["location"]
                dst_location = Location(dict_get(doc_dict, "destination.geo.country_name"), dict_get(doc_dict, "destination.geo.city_name"), long_lat["lat"], long_lat["lon"], asn=dict_get(doc_dict, "destination.as.number"), org=dict_get(doc_dict, "destination.as.organization.name"), certainty=80)
            except Exception as e:
                mlog.warning("create_flow_from_doc - Could not parse destination flow location from Elastic-SIEM document: " + str(e))
    else:
        dst_ip = cast_to_ipaddress(dict_get(doc_dict, "host.ip")[0])
        mlog.warning("create_flow_from_doc - No destination IP found in Elastic-SIEM document. Using host's IP: " + str(src_ip))


    # Get http object if applicable
    http = None
    if "http" in doc_dict:
        pass # TODO: Implement HTTP from Elastic-SIEM flow

    # Get dns object if applicable
    dns = None
    if "dns" in doc_dict:
        try:
            msg = doc_dict["message"]
            resolved_ip = None
            has_resp = False
            dns_type = "A" # Default type if unknown is A

            # Get the resolved IP Address from the message string using regex:
            resolved_ips = re.findall(r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", msg)
            resolved_ip = resolved_ips[0] if len(resolved_ips) > 0 else None
            resolved_ip = ".".join(resolved_ip) if resolved_ip is not None else None
            if resolved_ip is None:
                # Try find an ipv6 address
                resolved_ips = re.findall("([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})", msg)
                resolved_ip = resolved_ips[0] if len(resolved_ips) > 0 else None

            
            if resolved_ip is not None:
                try:
                    resolved_ip = cast_to_ipaddress(resolved_ip)
                    has_resp = True
                except Exception as e:
                    mlog.warning("create_flow_from_doc - DNS: Could not parse resolved IP from Elastic-SIEM document: " + str(e))
                    resolved_ip = None
            else:
                resolved_ip = None
            
            # Get type of DNS query
            if has_resp and type(resolved_ip) == ipaddress.IPv4Address:
                dns_type = "A"
            elif has_resp and dns_type(resolved_ip) is ipaddress.IPv6Address:
                dns_type = "AAAA"
                
            dns = DNSQuery(detection_id, type=dns_type, query=dict_get(doc_dict, "dns.question.name"), has_response=has_resp, query_response=resolved_ip)

        except Exception as e:
            mlog.warning("create_flow_from_doc - Could not parse flow's DNS from Elastic-SIEM document: " + str(e))

    # Create the flow object
    flow = ContextFlow(
        detection_id,
        dict_get(doc_dict, "@timestamp"),
        "Elastic-SIEM",
        src_ip,
        dict_get(doc_dict, "source.port"),
        dst_ip,
        dict_get(doc_dict, "destination.port"),
        dict_get(doc_dict, "network.protocol"),
        dict_get(doc_dict, "network.application"),
        None,
        None,
        None,
        dict_get(doc_dict, "source.bytes"),
        dict_get(doc_dict, "destination.bytes"),
        dict_get(doc_dict, "host.mac")[0],
        None,
        dict_get(doc_dict, "host.name"),
        None,
        dict_get(doc_dict, "event.action"),
        dict_get(doc_dict, "network.transport"),
        None,
        flow_source="Elastic Endpoint Security",
        source_location=src_location,
        destination_location=dst_location,
        http=http,
        dns_query=dns,
        detection_relevance=50
    )

    mlog.debug("Created flow: " + str(flow))
    return flow


def create_process_from_doc(mlog, doc_dict, detectionOnly=True):
    """Creates a ContextProcess object from a Elastic-SIEM document."""
    mlog.debug(
        "Creating ContextProcess object from Elastic-SIEM document."
    )

    dns_requests = None  # TODO: Implement create_dns_from_doc
    files = None  # TODO: Implement create_file_from_doc
    flows = None  # TODO: Implement create_flow_from_doc
    http_requests = None  # TODO: Implement create_http_from_doc

    created_files = []
    deleted_files = []
    modified_files = []

    # Get parent process entity to create a minimal process to link the current process to it
    parent = dict_get(doc_dict, "process.parent.entity_id")
    if not parent:
        parent = dict_get(doc_dict, "process.Ext.ancestry")
        if parent:
            parent = parent[0]
        else:
            parent = None

    children = []
    start_time = dict_get(doc_dict, "process.start"),
    if not start_time:
        mlog.warning("No explicit start time found for process. Using @timestamp of event.")
        start_time = dict_get(doc_dict, "@timestamp")

    # Try to create certificate object from process signature
    signature = None
    sign_raw = dict_get(doc_dict, "process.Ext.code_signature")
    if sign_raw:
        if type(sign_raw) == list:
            sign_raw = sign_raw[0]

        signer = dict_get(sign_raw, "subject_name")
        signature = Certificate(dict_get(doc_dict, "kibana.alert.uuid"), is_trusted=bool(dict_get(sign_raw, "trusted")), issuer=signer, subject=signer)

    sha256 = dict_get(doc_dict, "process.hash.sha256")
    if sha256 is None:
        mlog.warning("No SHA256 hash found for process. Using random hash instead.")
        # Create 64 random hex characters
        sha256 = ''.join(random.choice(string.hexdigits) for _ in range(64))

    # Create the process object
    process = ContextProcess(
        timestamp=dict_get(doc_dict, "@timestamp"),
        related_detection_uuid=dict_get(doc_dict, "kibana.alert.uuid"),
        process_name=dict_get(doc_dict, "process.name"),
        process_id=dict_get(doc_dict, "process.pid"),
        parent_process_name=dict_get(doc_dict, "process.parent.name"),
        parent_process_id=dict_get(doc_dict, "process.parent.pid"),
        parent_process_arguments=dict_get(doc_dict, "process.parent.args"),
        process_path=dict_get(doc_dict, "process.executable"),
        process_md5=dict_get(doc_dict, "process.hash.md5"),
        process_sha1=dict_get(doc_dict, "process.hash.sha1"),
        process_sha256=sha256,
        process_command_line=dict_get(doc_dict, "process.args"),
        process_username=dict_get(doc_dict, "user.name"),
        process_owner=dict_get(doc_dict, "user.name"),
        process_start_time=start_time,
        process_parent_start_time=dict_get(doc_dict, "process.parent.start"),
        process_current_directory=dict_get(doc_dict, "process.working_directory"),
        process_dns=dns_requests,
        process_http=http_requests,
        process_flow=flows,
        process_parent=parent,
        process_children=children,
        process_arguments=dict_get(doc_dict, "process.args"),
        process_signature=signature,
        created_files=created_files,
        deleted_files=deleted_files,
        modified_files=modified_files,
        process_uuid=dict_get(doc_dict, "process.entity_id"),
        is_complete=True,
    )

    mlog.debug("Created process: " + str(process.process_name) + " with UUID: " + str(process.process_uuid))
    return process

def create_file_from_doc(mlog, doc_dict, detection_id):
    """Creates a ContextFile object from a Elastic-SIEM document."""
    mlog.debug(
        "Creating ContextFile object from Elastic-SIEM document."
    )

    # Parse entropy as float if possible
    entropy = None
    try:
        entropy = dict_get(doc_dict, "file.Ext.entropy")
        if entropy:
            entropy = float(entropy)
    except Exception as e:
        pass

    # Create the file object
    file = ContextFile(
        detection_id,
        timestamp=dict_get(doc_dict, "@timestamp"),
        action=dict_get(doc_dict, "event.action"),
        file_name=dict_get(doc_dict, "file.name"),
        file_original_name=dict_get(doc_dict, "file.original.name"),
        file_path=dict_get(doc_dict, "file.path"),
        file_original_path=dict_get(doc_dict, "file.original.path"),
        file_extension=dict_get(doc_dict, "file.extension"),
        file_size=dict_get(doc_dict, "file.size"),
        file_header_bytes=dict_get(doc_dict, "file.header"),
        file_entropy=entropy
        # TODO: Add more fields if found
    )

    mlog.debug("Created file: " + str(file.file_name))
    return file

def create_registry_from_doc(mlog, doc_dict, detection_id):
    """Creates a ContextRegistry object from a Elastic-SIEM document."""
    mlog.debug(
        "Creating ContextRegistry object from Elastic-SIEM document."
    )

    # Create the registry object
    registry = ContextRegistry(
        detection_id,
        timestamp=dict_get(doc_dict, "@timestamp"),
        action=dict_get(doc_dict, "event.action"),
        registry_key=dict_get(doc_dict, "registry.key"),
        registry_value=dict_get(doc_dict, "registry.value"),
        registry_data=dict_get(doc_dict, "registry.data.bytes"),
        registry_data_type=dict_get(doc_dict, "registry.data.type"),
        registry_hive=dict_get(doc_dict, "registry.hive"),
        registry_path=dict_get(doc_dict, "registry.path"),
    )

    mlog.debug("Created registry: " + str(registry.registry_key))
    return registry


def get_all_indices(mlog, config, security_only=False):
    """Gets all indices from Elasticsearch.

    Args:
        mlog (logging_helper.Log): The logging object
        config (dict): The configuration dictionary for this integration

    Returns:
        list: A list of all indices
    """
    mlog.debug("get_all_indices() - called")

    if security_only:
        mlog.debug("get_all_indices() - only getting security indices")
        return [".alerts-security.alerts-default", "logs-*"]

    elastic_host = config["elastic_url"]
    elastic_user = config["elastic_user"]
    elastic_pw = config["elastic_password"]
    should_verify = config["elastic_verify_certs"]

    # Define headers and URL for Elasticsearch search
    headers = {
        "Content-Type": "application/json",
    }
    url = elastic_host + "/_cat/indices?format=json"

    # Get all indices from Elasticsearch
    mlog.debug("get_all_indices() - calling Elasticsearch at: " + url)
    try:
        response = requests.get(url, headers=headers, auth=(elastic_user, elastic_pw), verify=should_verify)
    except Exception as e:
        mlog.error("get_all_indices() - error while calling Elasticsearch: " + str(e))
        return []

    # Check if the response was successful
    if response.status_code != 200:
        mlog.error("get_all_indices() - Elasticsearch returned status code: " + str(response.status_code))
        return []

    # Parse the response
    try:
        response_json = response.json()
    except Exception as e:
        mlog.error("get_all_indices() - error while parsing Elasticsearch response: " + str(e))
        return []

    # Get all indices
    indices = []

    for index in response_json:
        indices.append(index["index"])

    mlog.debug("get_all_indices() - found " + str(len(indices)) + " indices")
    return indices


def search_entity_by_id(mlog, config, entity_id, entity_type="process", security_only=True):
    """Searches for an entity by its entity ID.

    Args:
        mlog (logging_helper.Log): The logging object
        config (dict): The configuration dictionary for this integration
        entity_id (str): The entity ID to search for
        entity_type (str): The type of entity to search for

    Returns:
        dict: The entity
    """
    mlog.debug("search_entity_by_id() - called with entity_id '" + str(entity_id) + "' and entity_type: " + entity_type)
    skip_cache = False

    # Check if entity_type is valid first
    valid_entity_types = ["network", "file", "parent_process", "process", "registry"]
    if entity_type not in valid_entity_types:
        raise NotImplementedError(f"search_entity_by_id() - entity_type '{entity_type}' not implemented")

    # Now, check if the enity is in the cache (except for parent_process)
    if entity_type != "parent_process": # Except for entity_type 'process' this will in the best case return 'empty' (literally) to indicate that the entity was not found previously and does not need to be searched. If it was found previously, it is not saved to the cache because of the size of the data.
        if entity_type == "network":
            cache_result = get_from_cache("elastic_siem", "flow_entities", entity_id)   
        elif entity_type == "file":
            cache_result = get_from_cache("elastic_siem", "file_entities", entity_id)
        elif entity_type == "registry":
            cache_result = get_from_cache("elastic_siem", "registry_entities", entity_id)
        else:
            cache_result = get_from_cache("elastic_siem", "entities", entity_id)
            if cache_result and len(cache_result) > 1:
                mlog.debug("Ignoring cache result because it contains more than one entity. Will search for it again.")
                skip_cache = True

        # If we found a result in the cache
        if cache_result is not None:
            if cache_result == "empty":
                mlog.debug("search_entity_by_id() - FOUND EMPTY entity in cache. Will not search for it again.")
                return None
            elif not skip_cache:
                mlog.debug("search_entity_by_id() - FOUND entity in cache.")
                return cache_result
        else:
            mlog.debug("search_entity_by_id() - entity NOT FOUND in cache")

    # If the entity_type is 'parent_process', print the appropriate debug message
    elif entity_type == "parent_process":
        mlog.debug("search_entity_by_id() - entity type is parent_process. Can't check cache.")


    elastic_host = config["elastic_url"]
    elastic_user = config["elastic_user"]
    elastic_pw = config["elastic_password"]
    should_verify = config["elastic_verify_certs"]
    lookback_time = f"now-{LOOKBACK_DAYS}d/d"

    # Define headers and URL for Elasticsearch search
    headers = {
        "Content-Type": "application/json",
    }

    # Chech index cache first for last successful indeces
    mlog.debug("search_entity_by_id() - Checking index cache for last successful indices to search first...")
    indices = get_from_cache("elastic_siem", "successful_indices", "LIST")
    if indices is not None:
        mlog.debug("search_entity_by_id() - found successful indices in cache. Checking them first.")
    else:
        mlog.debug("search_entity_by_id() - no successful indices found in cache to search first.")

    indices_all = get_all_indices(mlog, config, security_only=security_only)
    if indices is not None:
        indices = indices + indices_all
    else:
        indices = indices_all

    success = False
    mlog.debug(f"search_entity_by_id() - Searching for entity with ID {entity_id} in indices: " + str(indices)+ ". This may take a while...")

    for index in indices:
        url = f"{elastic_host}/{index}/_search?size=" + str(MAX_SIZE_ELASTICSEARCH_SEARCH)

        # Define Elasticsearch search query
        if entity_type == "process":
            search_query = {"query": {"bool": {"must": [{"match": {"process.entity_id": entity_id}}, {"range": {"@timestamp": {"gte": lookback_time}}}]}}}
        elif entity_type == "parent_process":
            search_query = {"query": {"bool": {"must": [{"match": {"process.parent.entity_id": entity_id}}, {"range": {"@timestamp": {"gte": lookback_time}}}]}}}
        elif entity_type == "file":
            search_query = {"query": {"bool": {"must": [{"match": {"process.entity_id": entity_id}}, {"match": {"event.category": "file"}}, {"range": {"@timestamp": {"gte": lookback_time}}}]}}}
        elif entity_type == "network":
            search_query = {"query": {"bool": {"must": [{"match": {"process.entity_id": entity_id}}, {"match": {"event.category": "network"}}, {"range": {"@timestamp": {"gte": lookback_time}}}]}}}
        elif entity_type == "registry":
            search_query = {"query": {"bool": {"must": [{"match": {"process.entity_id": entity_id}}, {"match": {"event.category": "registry"}}, {"range": {"@timestamp": {"gte": lookback_time}}}]}}}


        #mlog.debug(f"search_entity_by_id() - Searching index {index} for entity with URL: " + url + " and data: " + json.dumps(search_query)) | L2 DEBUG


        # Send Elasticsearch search request
        response = requests.post(url, headers=headers, auth=(elastic_user, elastic_pw), json=search_query, verify=should_verify)

        # Check if Elasticsearch search was successful
        if response.status_code != 200:
            if response.status_code == 404:
                #mlog.debug(f"search_entity_by_id() - Index {index}: Elasticsearch returned status code 404. Index does not exist.") | L2 DEBUG
                continue
            mlog.error(f"search_entity_by_id() - Elasticsearch search failed with status code {response.status_code}")
            continue

        #mlog.debug(f"search_entity_by_id() - Response text: {response.text}") | L2 DEBUG

        # Extract the entity from the Elasticsearch search response
        search_response = json.loads(response.text)
        if search_response["hits"]["total"]["value"] == 0:
            #mlog.debug(f"search_entity_by_id() - Index {index}: No entity found for entity_id {entity_id} and entity_type {entity_type}") | L2 DEBUG
            continue
        else:
            success = True
            break

    if not success:
        if not entity_type == "parent_process":
            mlog.warning(f"search_entity_by_id() - No entity found for entity_id '{entity_id}' and entity_type '{entity_type}'") # here a warning is logged because we expect to find at least one entity for a parent process
        else:
            mlog.debug(f"search_entity_by_id() - No entity found for entity_id '{entity_id}' and entity_type '{entity_type}'")   

        # Add empty entity to cache so that we don't search for it again
        if entity_type == "network":
            add_to_cache("elastic_siem", "flow_entities", str(entity_id), "empty")  

        elif entity_type == "file":
            add_to_cache("elastic_siem", "file_entities", str(entity_id), "empty") 
        
        elif entity_type == "registry":
            add_to_cache("elastic_siem", "registry_entities", str(entity_id), "empty")

        else:
            add_to_cache("elastic_siem", "entities", entity_id, "empty")
        return None
    
    if search_response["hits"]["total"]["value"] > 1 and entity_type == "process":
        mlog.warning(f"search_entity_by_id() - Found more than one entity for entity_id '{entity_id}' and entity_type '{entity_type}'") # finding more than one process for a process id is not expected

    if entity_type == "process":
        entity = search_response["hits"]["hits"][0]["_source"]
        mlog.debug(f"search_entity_by_id() - Entity found for entity_id '{entity_id}' and entity_type '{entity_type}': {json.dumps(entity)}")
        if len(entity) > 1:
            mlog.warning(f"search_entity_by_id() - Found more than one entity for entity_id '{entity_id}' and entity_type '{entity_type}'")

    else:
        mlog.debug(f"search_entity_by_id() - Found {search_response['hits']['total']['value']} entities for entity_id '{entity_id}' and entity_type '{entity_type}'")
        entity = search_response["hits"]["hits"]



    # Save entity to cache
    if entity_type == "process": # Other entity types are not cached as it is unlikely that they will be searched for again for another detection
        add_to_cache("elastic_siem", "entities", entity_id, entity)

    # Save index name to cache
    add_to_cache("elastic_siem", "successful_indices", "LIST", index)
    
    return entity


def acknowledge_alert(mlog, config, alert_id, index):
    """Acknowledges an alert in Elastic-SIEM.

    Args:
        mlog (logging_helper.Log): The logging object
        config (dict): The configuration dictionary for this integration
        alert_id (str): The ID of the alert to acknowledge

    Returns:
        None
    """
    mlog.debug("acknowledge_alert() called with alert_id: " + str(alert_id))

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

        if dict_get(response, "_shards.successful", False):
            mlog.info("Successfully acknowledged alert with id: " + alert_id)
            return True
        elif dict_get(response, "_shards.failed", False):
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
                dict_get(doc_dict, "kibana.alert.rule.uuid"),
                dict_get(doc_dict, "kibana.alert.rule.name"),
                dict_get(doc_dict, "kibana.alert.rule.severity"),
                description=dict_get(doc_dict, "kibana.alert.rule.description"),
                tags=dict_get(doc_dict, "kibana.alert.rule.tags"),
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

        # Most EDR detections are process related so check if a ContextProcess context can be created
        process = None
        if dict_get(doc_dict, "process.entity_id") is not None:
            process = create_process_from_doc(mlog, doc_dict)

        # Create the detection object
        detection = Detection(
            doc_dict["kibana.alert.uuid"],
            doc_dict["kibana.alert.rule.name"],
            rule_list,
            doc_dict["@timestamp"],
            description=doc_dict["kibana.alert.rule.description"],
            tags=doc_dict["kibana.alert.rule.tags"],
            source=dict_get(doc_dict, "host.hostname"),
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
    config, detection_report: DetectionReport, required_type: type, TEST=False, UUID=None, UUID_is_parent=False,  maxContext=50
) -> Union[ContextFlow, ContextLog, ContextProcess]:
    """Returns a DetectionReport object with context for the detections from the Elasic integration.

    Args:
        config (dict): The configuration dictionary for this integration
        detection (DetectionReport): The DetectionReport object to add context to
        required_type (type): The type of context to return. Can be one of the following:
            [ContextFlow, ContextLog]
        test (bool, optional): If set to True, dummy context data will be returned. Defaults to False.
        UUID (str, optional): Setting this will mean that a single object matching the Elastic-SIEM 'entity_id' will be returned. (Except when 'UUID_is_parent' is set). Defaults to None.
        UUID_is_parent (bool, optional):  Setting this will mean that all processes matching the Elastic-SIEM 'process.parent.entity_id' will be returned. Defaults to False.
        maxContext (int, optional): The maximum number of context objects to return. Defaults to -1 (no restriction).

    Returns:
        Union[ContextFlow, ContextLog]: The required context of type 'required_type'
    """
    mlog = init_logging(config)
    detection_report_str = "'" + detection_report.get_title() + "' (" + str(detection_report.uuid) + ")"
    uuid_str = ""
    if UUID is not None:
        uuid_str = " with UUID: " + str(UUID)
    mlog.info(f"zs_provide_context_for_detections() called for detection report: {detection_report_str} and required_type: {required_type}" + uuid_str)

    return_objects = []
    provided_types = []
    provided_types.append(ContextFlow)
    provided_types.append(ContextLog)
    provided_types.append(ContextProcess)
    provided_types.append(ContextFile)
    provided_types.append(ContextRegistry)

    detection_name = detection_report.detections[0].name
    detection_id = detection_report.detections[0].uuid

    if required_type not in provided_types:
        mlog.error("The required type is not provided by this integration. '" + str(required_type) + "' is not in " + str(provided_types))
        raise TypeError("The required type is not provided by this integration.")

    if TEST:  # When called from unit tests, return dummy data. Can be removed in production.
        mlog.info("Running in test mode. Returning dummy data.")
        if required_type == ContextFlow:
            context_object = ContextFlow(
                detection_report.uuid, datetime.datetime.now(), "Elastic-SIEM", "10.0.0.1", 123, "123.123.123.123", 80, "TCP"
            )
        elif required_type == ContextProcess:
            context_object = ContextProcess(
                uuid.uuid4(), datetime.datetime.now(), detection_report.uuid, "test.exe", 123, process_start_time=datetime.datetime.now()
            )
        elif required_type == ContextLog:
            context_object = ContextLog(detection_report.uuid, datetime.datetime.now(), "Some log message", "Elastic-SIEM", log_source_ip="10.0.0.3")
        return_objects.append(context_object)
        detection_example = detection_report.detections[0]
        detection_id = detection_example.vendor_id

    # ...
    # ...
    if not TEST:
        if required_type == ContextProcess:
            if UUID is None:
                mlog.info(
                    "No UUID provided. This implies that the detection is not from Elastic SIEM itself. Will return relevant processes if found."
                )
                # ... TODO: Get all processes related to the detection
            else:
                if UUID_is_parent:
                    mlog.info("Process Parent UUID provided. Will return all processes with parent UUID: " + UUID + " (meaning all children processes)")
                    docs = search_entity_by_id(mlog, config, UUID, entity_type="parent_process")

                    if docs == None or len(docs) == 0:
                        mlog.info("No processes found which have a parent with UUID: " + UUID + " (meaning no child processes found)")
                        return None
                    else:
                        counter = 0
                        for doc in docs:
                            event_category = doc["_source"]["event"]["category"][0]
                            if event_category != "process":
                                mlog.info("Skipping adding event with category: " + event_category)
                                continue
                            if maxContext != -1 and counter >= maxContext:
                                mlog.info("Reached given maxContext limit (" + str(maxContext) + "). Will not return more context.")
                                break
                            process = create_process_from_doc(mlog, doc["_source"])
                            return_objects.append(process)
                            counter += 1
                else:
                    mlog.info("UUID provided. Will return the single process with UUID: " + UUID)
                    doc = search_entity_by_id(mlog, config, UUID, entity_type="process")
                    if doc is not None:
                        process = create_process_from_doc(mlog, doc)
                        return_objects.append(process)

        elif required_type == ContextFlow:
            # TODO: Implement seach in Suricata Indices as well

            if len(UUID) > 69: # TODO: Implement searching flow by Process / File Entity ID
                mlog.info("Process Entity ID provided. Will return all flows for process with Entity ID: " + UUID)
                flow_docs = search_entity_by_id(mlog, config, UUID, entity_type="network", security_only=True)

                if flow_docs == None or len(flow_docs) == 0:
                    mlog.info("No flows found for process with Entity ID: " + UUID)
                    return None
                
                for doc in flow_docs:
                    return_objects.append(create_flow_from_doc(mlog, doc["_id"], doc["_source"], detection_id))
            else:
                mlog.error("UUID does not match either a valid Elastic Entity ID")
                return None
                
        elif required_type == ContextFile:
            if UUID is None: # UUID in this context means process ID, SHA256 or EntityID
                # Need a process ID for now
                return NotImplementedError
            else:
                if len(UUID) > 69: # TODO: Implement searching file by Process / File Entity ID
                    mlog.info("Process Entity ID provided. Will return file with Entity ID: " + UUID)
                    file_docs = search_entity_by_id(mlog, config, UUID, entity_type="file", security_only=True)

                    if file_docs == None or len(file_docs) == 0:
                        mlog.info("No files found with Entity ID: " + UUID)
                        return None
                    
                    for doc in file_docs:
                        file_obj = create_file_from_doc(mlog, doc["_source"], detection_id)
                        return_objects.append(file_obj)
                else:
                    mlog.error("UUID does not match either a valid Elastic Entity ID")
                    return None
                
        elif required_type == ContextRegistry:
            if UUID is None:
                # Need a process ID for now
                return NotImplementedError
            else:
                if len(UUID) > 69:
                    mlog.info("Process Entity ID provided. Will return registry with Entity ID: " + UUID)
                    registry_docs = search_entity_by_id(mlog, config, UUID, entity_type="registry", security_only=True)

                    if registry_docs == None or len(registry_docs) == 0:
                        mlog.info("No registry entries found with Entity ID: " + UUID)
                        return None
                    
                    for doc in registry_docs:
                        registry_obj = create_registry_from_doc(mlog, doc["_source"], detection_id)
                        return_objects.append(registry_obj)
    # ...
    # ...
    if len(return_objects) == 0:
        mlog.info(
            "zs_provide_context_for_detections() found no context for detection '" + detection_name + "' and required_type: " + str(required_type)
        )
        return None

    for context_object in return_objects:
        if context_object != None:
            if type(context_object) != required_type:  # Sanity check that the 'return_object' has the required type
                mlog.error("The returned object is not of the required type. Returning None.")
                return None
            mlog.info(
                f"zs_provide_context_for_detections() found context for detection '{detection_name}' ({detection_id}) and required_type: {required_type}"
            )
            if VERBOSE_DEBUG:
                mlog.debug(
                    "zs_provide_context_for_detections() returned the following context: "
                    + str(context_object)
                    + " for detection: "
                    + str(detection_report)
                )
        else:
            mlog.info(
                "zs_provide_context_for_detections() found no context for detection: '" + detection_name + "' and required_type: " + str(required_type)
            )
    return return_objects


if __name__ == "__main__":
    # This integration should not be called directly besides running the integration setup!
    main()
