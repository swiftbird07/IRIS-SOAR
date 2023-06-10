# Tests the Elastic SIEM integration

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, ContextProcess, ContextLog, ContextFlow
from integrations.elastic_siem import zs_provide_new_detections, zs_provide_context_for_detections, acknowledge_alert, search_entity_by_id
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import uuid

ENTITY_ID = "ODkzYjNkNDAtYTdiNy00MjdjLWJhYjItM2U4NGEzZjMzNWMxLTkwMjAtMTY4NDUxMjc4Mi44MTkzMTM2MDA="
ENTITY_TYPE = "process"

def test_zs_provide_new_detections():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    detectionArray = zs_provide_new_detections(integration_config, TEST="OFFLINE")
    assert type(detectionArray) == list, "zs_provide_new_detections() should return a list of Detection objects"
    for detection in detectionArray:
        assert type(detection) == Detection, "zs_provide_new_detections() found an invalid Detection object in the list"


def test_zs_provide_context_for_detections():
    mlog = logging_helper.Log("test_elastic_siem")
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

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

    # Test the function
    flows = zs_provide_context_for_detections(integration_config, detection_report, ContextFlow, TEST=True, UUID=86677)
    assert type(flows[0]) == ContextFlow, "zs_provide_context_for_detections() should return a ContextFlow object"

    processes = zs_provide_context_for_detections(integration_config, detection_report, ContextProcess, TEST=True)
    assert type(processes[0]) == ContextProcess, "zs_provide_context_for_detections() should return a ContextProcess object"

    events = zs_provide_context_for_detections(integration_config, detection_report, ContextLog, TEST=True)
    assert type(events[0]) == ContextLog, "zs_provide_context_for_detections() should return a ContextLog object"

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


def test_online_new_detections():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    detectionArray = zs_provide_new_detections(integration_config, TEST="ONLINE")
    assert type(detectionArray) == list, "zs_provide_new_detections() should return a list of Detection objects"
    for detection in detectionArray:
        assert type(detection) == Detection, "zs_provide_new_detections() found an invalid Detection object in the list"


def test_online_context_for_detections():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]
    
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


    flows = zs_provide_context_for_detections(integration_config, detection_report, ContextFlow, TEST=False, UUID=ENTITY_ID)
    assert type(flows[0]) == ContextFlow, "zs_provide_context_for_detections() should return a ContextFlow object"


#test_online_new_detections()
