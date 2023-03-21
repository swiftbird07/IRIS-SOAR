# Tests the Elastic SIEM integration

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, ContextProcess, ContextLog, ContextFlow
from integrations.elastic_siem import zs_provide_new_detections, zs_provide_context_for_detections
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper


def test_zs_provide_new_detections():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["elastic_siem"]

    detectionArray = zs_provide_new_detections(integration_config, TEST=True)
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
    detection = Detection("456", "Some Detection", ruleList)

    detectionList = []
    detectionList.append(detection)
    detectionReport = DetectionReport(detectionList)
    assert (
        detectionReport != None
    ), "DetectionReport class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()

    # Test the function
    flow = zs_provide_context_for_detections(integration_config, detectionReport, ContextFlow, TEST=True)
    assert type(flow) == ContextFlow, "zs_provide_context_for_detections() should return a ContextFlow object"

    process = zs_provide_context_for_detections(integration_config, detectionReport, ContextProcess, TEST=True)
    assert type(process) == ContextProcess, "zs_provide_context_for_detections() should return a ContextProcess object"

    event = zs_provide_context_for_detections(integration_config, detectionReport, ContextLog, TEST=True)
    assert type(event) == ContextLog, "zs_provide_context_for_detections() should return a ContextLog object"

    # Print the results
    mlog.info("Process context:")
    mlog.info(process)
    mlog.info("Flow context:")
    mlog.info(flow)
    mlog.info("Event context:")
    mlog.info(event)
