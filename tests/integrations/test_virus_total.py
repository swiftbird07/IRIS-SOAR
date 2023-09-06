# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the virus_total integration.

import pytest

from lib.class_helper import (
    Alert,
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
from integrations.virus_total import irsoar_provide_context_for_alerts
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import ipaddress


def test_irsoar_provide_context_for_alerts():
    mlog = logging_helper.Log("test_elastic_siem")
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["virus_total"]

    # Prepare a CaseFile object
    rule = Rule("123", "Some Rule", 0)

    ruleList = []
    ruleList.append(rule)
    alert = Alert("456", "Some Alert", ruleList, datetime.datetime.now())

    alertList = []
    alertList.append(alert)
    case_file = CaseFile(alertList)
    assert (
        case_file != None
    ), "CaseFile class could not be initialized"  # Sanity check - should be already tested by test_isoar_lib.py -> test_class_helper()

    # Test IP search
    result1 = irsoar_provide_context_for_alerts(
        integration_config,
        case_file,
        ContextThreatIntel,
        TEST=True,
        search_type=ipaddress.IPv4Address,
        search_value=ipaddress.ip_address("136.243.123.201"),
        wait_if_api_quota_exceeded=True,
    )
    assert type(result1) == ContextThreatIntel, "irsoar_provide_context_for_alerts() should return a ContextThreatIntel object"

    # Test domain search
    result2 = irsoar_provide_context_for_alerts(
        integration_config, case_file, ContextThreatIntel, TEST=True, search_type=DNSQuery, search_value="www.google.com"
    )
    assert type(result2) == ContextThreatIntel, "irsoar_provide_context_for_alerts() should return a ContextThreatIntel object"

    # Test process search
    result3 = irsoar_provide_context_for_alerts(
        integration_config,
        case_file,
        ContextThreatIntel,
        TEST=True,
        search_type=ContextProcess,
        search_value="6f3b9dda23c69c097372ef91fd09420a",
        wait_if_api_quota_exceeded=True,
    )
    assert type(result3) == ContextThreatIntel, "irsoar_provide_context_for_alerts() should return a ContextThreatIntel object"

    # Test URL search
    result4 = irsoar_provide_context_for_alerts(
        integration_config,
        case_file,
        ContextThreatIntel,
        TEST=True,
        search_type=HTTP,
        search_value="https://www.google.co.uk",
        wait_if_api_quota_exceeded=True,
    )
    assert type(result4) == ContextThreatIntel, "irsoar_provide_context_for_alerts() should return a ContextThreatIntel object"

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
