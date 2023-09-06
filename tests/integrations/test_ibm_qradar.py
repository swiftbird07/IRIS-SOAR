# Tests the IBM QRadar integration

import pytest

from lib.class_helper import Alert, CaseFile, Rule, ContextProcess, ContextLog, ContextFlow, ContextFile
from integrations.ibm_qradar import irsoar_provide_new_alerts, irsoar_provide_context_for_alerts
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import uuid

OFFENSE_ID = "1438"  # The ID of an offense that exists in the QRadar test environment


def test_irsoar_provide_new_alerts():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["ibm_qradar"]

    alertArray = irsoar_provide_new_alerts(integration_config, TEST=True)
    assert type(alertArray) == list, "irsoar_provide_new_alerts() should return a list of Alert objects"
    assert len(alertArray) > 0, "irsoar_provide_new_alerts() should return a list of Alert objects"
    for alert in alertArray:
        assert type(alert) == Alert, "irsoar_provide_new_alerts() found an invalid Alert object in the list"


def test_irsoar_provide_context_for_alerts():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["ibm_qradar"]

    # Prepare a CaseFile object
    rule = Rule("123", "Some Rule", 0)

    ruleList = []
    ruleList.append(rule)
    alert = Alert("789", "A QRadar Alert", ruleList, datetime.datetime.now(), uuid=OFFENSE_ID)

    alertList = []
    alertList.append(alert)
    case_file = CaseFile(alertList)
    assert (
        case_file != None
    ), "CaseFile class could not be initialized"  # Sanity check - should be already tested by test_isoar_lib.py -> test_class_helper()

    # Get the context
    alertArray = irsoar_provide_context_for_alerts(
        case_file, ContextFlow, TEST=True, search_type="offense", search_value=OFFENSE_ID
    )
    assert type(alertArray) == list, "irsoar_provide_context_for_alerts() should return a list of ContextFlow objects"
    assert len(alertArray) > 0, "irsoar_provide_context_for_alerts() should return a list of ContextFlow objects"
    for alert in alertArray:
        assert type(alert) == ContextFlow, "irsoar_provide_context_for_alerts() found an invalid ContextFlow object in the list"

    alertArray = irsoar_provide_context_for_alerts(
        case_file, ContextLog, TEST=True, search_type="offense", search_value=OFFENSE_ID
    )
    assert type(alertArray) == list, "irsoar_provide_context_for_alerts() should return a list of ContextLog objects"
    assert len(alertArray) > 0, "irsoar_provide_context_for_alerts() should return a list of ContextLog objects"
    for alert in alertArray:
        assert type(alert) == ContextLog, "irsoar_provide_context_for_alerts() found an invalid ContextLog object in the list"

    alertArray = irsoar_provide_context_for_alerts(
        case_file, ContextFile, TEST=True, search_type="offense", search_value=OFFENSE_ID
    )
    assert type(alertArray) == list, "irsoar_provide_context_for_alerts() should return a list of ContextFile objects"
    assert len(alertArray) > 0, "irsoar_provide_context_for_alerts() should return a list of ContextFile objects"
    for alert in alertArray:
        assert type(alert) == ContextFile, "irsoar_provide_context_for_alerts() found an invalid ContextFile object in the list"
