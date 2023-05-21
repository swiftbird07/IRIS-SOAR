# Tests the Znuny OTRS integration

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, ContextProcess, ContextLog, ContextFlow
from integrations.znuny_otrs import zs_create_ticket, zs_integration_setup, zs_provide_context_for_detections, zs_provide_new_detections
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import uuid

# Test ticket creation
def test_zs_create_ticket():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["znuny_otrs"]

    # Prepare a DetectionReport object
    rule = Rule("123", "Some Rule", 0)

    ruleList = []
    ruleList.append(rule)
    detection = Detection("456", "Some Detection", ruleList, datetime.datetime.now(), "Some description")

    detectionList = []
    detectionList.append(detection)
    detection_report = DetectionReport(detectionList)
    assert (
        detection_report != None
    ), "DetectionReport class could not be initialized"  # Sanity check - should be already tested by test_zsoar_lib.py -> test_class_helper()

    # Test the function
    ticket_id = zs_create_ticket(cfg, detection_report, True)
    assert type(ticket_id) == str, "zs_create_ticket() should return a string with the ticket ID"

    # Print the results
    mlog = logging_helper.Log("test_znuny_otrs")
    mlog.info("Ticket ID:")
    mlog.info(ticket_id)


#test_zs_create_ticket()