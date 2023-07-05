# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the virus_total integration.

import pytest

from lib.class_helper import (
    Detection,
    CaseFile,
    Rule,
    ContextProcess,
    ContextLog,
    ContextFlow,
    ContextFile,
    ContextThreatIntel,
    ThreatIntel,
    HTTP,
    DNSQuery,
)
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

    # Prepare a CaseFile object
    rule = Rule("123", "Some Rule", 0)

    ruleList = []
    ruleList.append(rule)
    detection = Detection("456", "Some Detection", ruleList, datetime.datetime.now())

    detectionList = []
    detectionList.append(detection)
    case_file = CaseFile(detectionList)
    assert (
        case_file != None
    ), "CaseFile class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()

    # Test IP search
    result1 = zs_provide_context_for_detections(
        integration_config,
        case_file,
        ContextThreatIntel,
        TEST=True,
        search_type=ipaddress.IPv4Address,
        search_value=ipaddress.ip_address("136.243.123.201"),
        wait_if_api_quota_exceeded=True,
    )
    assert type(result1) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Test domain search
    result2 = zs_provide_context_for_detections(
        integration_config, case_file, ContextThreatIntel, TEST=True, search_type=DNSQuery, search_value="www.google.com"
    )
    assert type(result2) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Test process search
    result3 = zs_provide_context_for_detections(
        integration_config,
        case_file,
        ContextThreatIntel,
        TEST=True,
        search_type=ContextProcess,
        search_value="6f3b9dda23c69c097372ef91fd09420a",
        wait_if_api_quota_exceeded=True,
    )
    assert type(result3) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Test URL search
    result4 = zs_provide_context_for_detections(
        integration_config,
        case_file,
        ContextThreatIntel,
        TEST=True,
        search_type=HTTP,
        search_value="https://www.google.co.uk",
        wait_if_api_quota_exceeded=True,
    )
    assert type(result4) == ContextThreatIntel, "zs_provide_context_for_detections() should return a ContextThreatIntel object"

    # Print the results
    print("IP search result:")
    print(result1)
    print("Domain search result:")
    print(result2)
    print("Process search result:")
    print(result3)
    print("URL search result:")
    print(result4)
    print("Test finished")
