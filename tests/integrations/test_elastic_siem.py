# Tests the Elastic SIEM integration

import pytest

from lib.class_helper import Alert, CaseFile, Rule, ContextProcess, ContextLog, ContextFlow
from integrations.elastic_siem import (
    irsoar_provide_new_alerts,
    irsoar_provide_context_for_alerts,
    acknowledge_alert,
    search_entity_by_id,
)
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import uuid

ENTITY_ID = "YjExNmM1NTYtNGNmMi00NTc5LWEwOGQtODU5OTIwMjVmMjNmLTE5MjQ2ODUtMTY4ODA2MTkxOA=="
ENTITY_TYPE = "process"


def test_irsoar_provide_new_alerts():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    alertArray = irsoar_provide_new_alerts(integration_config, TEST="OFFLINE")
    assert type(alertArray) == list, "irsoar_provide_new_alerts() should return a list of Alert objects"
    for alert in alertArray:
        assert type(alert) == Alert, "irsoar_provide_new_alerts() found an invalid Alert object in the list"


def test_irsoar_provide_context_for_alerts():
    mlog = logging_helper.Log("test_elastic_siem")
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

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

    # Test the function
    flows = irsoar_provide_context_for_alerts(integration_config, case_file, ContextFlow, TEST=True, search_value=86677)
    assert type(flows[0]) == ContextFlow, "irsoar_provide_context_for_alerts() should return a ContextFlow object"

    processes = irsoar_provide_context_for_alerts(integration_config, case_file, ContextProcess, TEST=True)
    assert type(processes[0]) == ContextProcess, "irsoar_provide_context_for_alerts() should return a ContextProcess object"

    events = irsoar_provide_context_for_alerts(integration_config, case_file, ContextLog, TEST=True)
    assert type(events[0]) == ContextLog, "irsoar_provide_context_for_alerts() should return a ContextLog object"

    # Print the results
    mlog.info("Process context:")
    mlog.info(processes[0])
    mlog.info("Flow context:")
    mlog.info(flows[0])
    mlog.info("Event context:")
    mlog.info(events[0])


def test_acknowledge_alert():
    # Prepare the config and logger
    mlog = logging_helper.Log("test_elastic_siem")
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    # Get a valid alert ID from kibana

    # Test the function
    result = acknowledge_alert(
        mlog,
        integration_config,
        "add1dd52e51cea326ba6fdb35b4c9400a768ad9d2c5ef02d94d852b72c51c1f3",
        ".internal.alerts-security.alerts-default-000001",
    )
    assert result == True, "acknowledge_alert() did not return True"


def test_search_entity_by_entity_id():
    # Prepare the config and logger
    mlog = logging_helper.Log("test_elastic_siem")
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    # Test the function
    result = search_entity_by_id(mlog, integration_config, ENTITY_ID, ENTITY_TYPE)
    assert result != None, "search_enity_by_entity_id() did not return a result"


# Omline tests


def test_online_new_alerts():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    alertArray = irsoar_provide_new_alerts(integration_config, TEST="ONLINE")
    assert type(alertArray) == list, "irsoar_provide_new_alerts() should return a list of Alert objects"
    for alert in alertArray:
        assert type(alert) == Alert, "irsoar_provide_new_alerts() found an invalid Alert object in the list"


def test_online_context_for_alerts():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

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

    flows = irsoar_provide_context_for_alerts(integration_config, case_file, ContextFlow, TEST=False, search_value=ENTITY_ID)
    assert type(flows[0]) == ContextFlow, "irsoar_provide_context_for_alerts() should return a ContextFlow object"


# test_online_new_alerts()
