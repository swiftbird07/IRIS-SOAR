# Tests the Elastic SIEM integration

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, Process, LogMessage, NetworkFlow
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
    detection_report = DetectionReport(detectionList)
    assert (
        detection_report != None
    ), "DetectionReport class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()

    # Test the function
    flows = zs_provide_context_for_detections(integration_config, detection_report, NetworkFlow, TEST=True)
    assert type(flows[0]) == NetworkFlow, "zs_provide_context_for_detections() should return a ContextFlow object"

    processes = zs_provide_context_for_detections(integration_config, detection_report, Process, TEST=True)
    assert type(processes[0]) == Process, "zs_provide_context_for_detections() should return a ContextProcess object"

    events = zs_provide_context_for_detections(integration_config, detection_report, LogMessage, TEST=True)
    assert type(events[0]) == LogMessage, "zs_provide_context_for_detections() should return a ContextLog object"

    # Print the results
    mlog.info("Process context:")
    mlog.info(processes[0])
    mlog.info("Flow context:")
    mlog.info(flows[0])
    mlog.info("Event context:")
    mlog.info(events[0])


test_zs_provide_context_for_detections()
