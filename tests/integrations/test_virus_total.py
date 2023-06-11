# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the virus_total integration.

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, ContextProcess, ContextLog, ContextFlow, ContextFile, ContextThreatIntel, ThreatIntel, HTTP, DNSQuery
from integrations.virus_total import zs_provide_context_for_detections
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import ipaddress

def test_zs_provide_context_for_detections():
    mlog = logging_helper.Log("test_elastic_siem")
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["virus_total"]

    # Prepare a DetectionReport object
    rule = Rule("123", "Some Rule", 0)

    ruleList = []
    ruleList.append(rule)
    detection = Detection("456", "Some Detection", ruleList, datetime.datetime.now())

    detectionList = []
    detectionList.append(detection)
    detection_report = DetectionReport(detectionList)
    assert (
        detection_report != None
    ), "DetectionReport class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()

    # Test IP search
    result = zs_provide_context_for_detections(integration_config, detection_report, ContextThreatIntel, TEST=True, search_type=ipaddress.IPv4Address, search_value=ipaddress.ip_address("1.1.1.1"))
    assert type(result) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Test domain search
    result = zs_provide_context_for_detections(integration_config, detection_report, ContextThreatIntel, TEST=True, search_type=DNSQuery, search_value="www.google.com")
    assert type(result) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Test process search
    result = zs_provide_context_for_detections(integration_config, detection_report, ContextThreatIntel, TEST=True, search_type=ContextProcess, search_value="ccdef4b25564f424772317356e27e6aa51976d2805594024b30f7b852f1ccf34")
    assert type(result) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Test URL search
    result = zs_provide_context_for_detections(integration_config, detection_report, ContextThreatIntel, TEST=True, search_type=HTTP, search_value="https://www.google.com")
    assert type(result) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"