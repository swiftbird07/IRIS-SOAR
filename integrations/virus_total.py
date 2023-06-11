# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with VirusTotal Threat Intelligence.
#
# This module is capable of:
# [ ] Providing context for detections of type [ContextThreatIntel]
# [ ] User interactive setup.
#
# Integration Version: 0.0.1

import logging
import datetime
import requests
from ssl import create_default_context
import uuid
import json
import ipaddress
import re
import random
import string
import time

import lib.logging_helper as logging_helper

# For context for detections:
from lib.class_helper import DetectionReport, ThreatIntel, ContextThreatIntel, HTTP, DNSQuery, ContextFile, ContextProcess
from lib.generic_helper import dict_get, get_from_cache, add_to_cache

THRESHOLD_MAX_TRIES_API_QUOTA_EXCEEDED = 5 # The maximum number of times the API call will be retried if the API quota is exceeded


def handle_response(response, cache, search_value, search_type, detection_id, mlog, wait_if_api_quota_exceeded, tries=0):
    if cache or response.status_code == 200:
        if not cache:
            response_json = response.json()
        else:
            response_json = response

        intel = []

         # For file/process related Threat Intel
        if "scans" in response_json:

            if not cache:
                mlog.info(f"VirusTotal API call for {str(search_type)} '{search_value}' returned data.")
                add_to_cache("virus_total", str(search_type), str(search_value), response.json())

            scans = response_json["scans"]
            
            for scan in scans:
                entry = scans[scan]
                result = "malicious" if entry["detected"] else ""
                threat_name = entry["result"]
                
                if threat_name != None:
                    if "heuristic" in threat_name.lower():
                        confidence = 10
                    elif "riskware" in threat_name.lower():
                        confidence = 25
                    else:
                        confidence = 80

                intel.append(ThreatIntel(
                    time_requested=datetime.datetime.now(),
                    engine=scan,
                    is_known=True if entry["detected"] else False,
                    is_hit=True if entry["detected"] else False,
                    hit_type="malicious" if entry["detected"] else "",
                    threat_name=threat_name if entry["detected"] else "",
                    confidence=confidence if entry["detected"] else "",
                    engine_version=entry["version"],
                    engine_last_updated=entry["update"],
                ))

                mlog.debug(f"Added engine '{scans[scan]}' to context for {str(search_type)} '{search_value}'.")

        # For internet related Threat Intel
        if "data" in response_json:

            if not cache:
                mlog.info(f"VirusTotal API call for {str(search_type)} '{search_value}' returned data.")
                add_to_cache("virus_total", str(search_type), str(search_value), response.json())
            try:
                scans = response_json["data"]["attributes"]["last_analysis_results"]
            except KeyError:
                scans = response_json["data"]["attributes"]["results"]

            for entry in scans:
                if scans[entry]["result"] != None:

                    entry = scans[entry]
                    result = entry["result"]

                    if "suspicous" in result:
                        confidence = 10
                    elif " ai" in result or "machine learning" in result or "ml" in result:
                        confidence = 20
                    else:
                        confidence = 80

                    intel.append(ThreatIntel(
                        time_requested=datetime.datetime.now(),
                        engine=entry["engine_name"],
                        is_known=True if entry["category"] not in ("undetected", "timeout") else False,
                        is_hit=True if entry["category"] in ("suspicious", "malicious") else False,
                        hit_type=entry["category"] if entry["category"] in ("suspicious", "malicious") else "",
                        threat_name=entry["result"] if entry["category"] in ("suspicious", "malicious") else "",
                        confidence=confidence if entry["category"] not in ("undetected", "timeout") else "",
                        method=entry["method"]
                    ))

        if len(intel) > 0:
            mlog.info(f"VirusTotal API for {str(search_type)} '{search_value}' returned {len(intel)} context entries.")
            context = ContextThreatIntel(search_type, search_value, "Virus Total API", datetime.datetime.now(), intel, related_detection_uuid=detection_id)
            # TODO Add last certificate, etc...
            return context
        else:
            mlog.error(f"VirusTotal API call for {str(search_type)} '{search_value}' did not return any data.")
            return None
    

    elif response.status_code == 204:
        mlog.error(f"VirusTotal API call for {str(search_type)} '{search_value}' returned status code 204. This means that the API quota is exceeded.")
        if wait_if_api_quota_exceeded:

            if tries >= THRESHOLD_MAX_TRIES_API_QUOTA_EXCEEDED:
                mlog.error(f"VirusTotal API call for {str(search_type)} '{search_value}' returned status code 204 {str(tries)} times in a row (above threshold). Aborting.")
                return None
            
            mlog.info(f"Waiting for 15 seconds and then retrying.")
            time.sleep(15)
            return handle_response(response, cache, search_value, search_type, detection_id, mlog, wait_if_api_quota_exceeded, tries=tries+1)
    else:
        mlog.error(f"VirusTotal API call for {str(search_type)} '{search_value}' failed with status code '{response.status_code}'.")
        return None


def zs_provide_context_for_detections(
    config, detection_report: DetectionReport, required_type: type, TEST=False, search_type="IP", search_value=None, maxContext=50, wait_if_api_quota_exceeded=False) -> ContextThreatIntel:
    """Returns a DetectionReport object with context for the detections from the Virus Total integration.

    Args:
        config (dict): The configuration dictionary for this integration
        detection (DetectionReport): The DetectionReport object to add context to
        required_type (type): The type of context to return. Can be one of the following:
            [ContextThreatIntel]
        TEST (bool, optional): If set to True, the function will return a test object. Defaults to False.
        search_type (str, optional): The type of the search. Can be one of the following:
            [IP, DOMAIN, URL, HASH]. Defaults to "IP".
        search_value (str, optional): The value (indicator) to search for. Defaults to None.
        maxContext (int, optional): The maximum number of context entries to return. Defaults to 50.

    Returns:
        ContextThreatIntel: A ContextThreatIntel object with context for the detections
    """
    # Check if integration is enabled
    if config["enabled"] == False:
        return None
    
    # Initialize the logger
    log_level_file = config["logging"]["log_level_file"]  # be aware that only configs from this integration are available not the general config
    log_level_stdout = config["logging"]["log_level_stdout"]
    log_level_syslog = config["logging"]["log_level_syslog"]
    mlog = logging_helper.Log(__name__, log_level_stdout=log_level_stdout, log_level_file=log_level_file)

    # Check if the required type is supported
    if required_type not in [ContextThreatIntel]:
        mlog.log_critical(f"Required context type '{required_type}' is not supported for this integration.")
        raise ValueError(f"Required context type '{required_type}' is not supported for this integration.")
    
    # Check if the search type is supported
    if search_type not in (ipaddress.IPv4Address, ipaddress.IPv6Address, HTTP, DNSQuery, ContextFile, ContextProcess) :
        mlog.log_critical(f"Search type '{search_type}' is not supported for this integration.")
        raise ValueError(f"Search type '{search_type}' is not supported for this integration.")
    
    # Check if the search value is set
    if search_value is None or search_value == "":
        mlog.log_critical(f"Search value is not set.")
        raise ValueError(f"Search value is not set.")
    
    detection_name = detection_report.detections[0].name
    detection_id = detection_report.detections[0].uuid
    
    
    mlog.info(f"Providing context for detection '{detection_name}' with ID '{detection_id}'. Search indicator type is '{search_type}' and searched value is '{search_value}'.")
    # Get the context from VirusTotal
    cache = get_from_cache("virus_total", str(search_type), str(search_value))
    if cache:
        mlog.info(f"{str(search_type)} -'{search_value}' is in the cache. Returning cached context.")
        response = cache
    
    api_key = config["api_key"]
    verify_certs = config["verify_certs"]
    params = None

    if search_type == ipaddress.IPv4Address or search_type == ipaddress.IPv6Address:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{search_value}"
    elif search_type == DNSQuery:
        url = f"https://www.virustotal.com/api/v3/domains/{search_value}"

    elif search_type == HTTP:
        search_value = (search_value.encode()).decode().strip("=")
        vt_url = "https://www.virustotal.com/api/v3/urls"
        payload = "url=" + search_value

        headers = {
            "Accept": "application/json",
            "x-apikey": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        response_url_req = requests.request(
            "POST", vt_url, data=payload, headers=headers
        )
        response_url_req_json = response_url_req.json()

        id_url_analysis = response_url_req_json["data"]["id"]
        mlog.info(f"VirusTotal API call for URL '{search_value}' returned analysis ID '{id_url_analysis}'.")
        url = "https://www.virustotal.com/api/v3/analyses/" + id_url_analysis

    elif search_type == ContextProcess:
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {"apikey": api_key, "resource": search_value}
        
    else:
        mlog.critical(f"Search type '{search_type}' is not supported for this integration.")
        raise TypeError(f"Search type '{search_type}' is not supported for this integration.")
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    if not cache:
        response = requests.request("GET", url, headers=headers, verify=verify_certs, params=params)
    
    return handle_response(response, cache, search_value, search_type, detection_id, mlog, wait_if_api_quota_exceeded)





