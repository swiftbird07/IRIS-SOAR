# Tests the Znuny OTRS integration

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, ContextProcess, ContextLog, ContextFlow
from integrations.znuny_otrs import zs_create_ticket, zs_integration_setup, zs_provide_context_for_detections, zs_provide_new_detections, zs_add_note_to_ticket
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import uuid


# Test ticket creation
def test_zs_create_ticket():
    TEST_ONLINE = False # Set to True to test the integration with changings to a real OTRS instance

    # Prepare the config
    cfg = config_helper.Config().cfg

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
    ticket_id = zs_create_ticket(detection_report, not TEST_ONLINE)
    if TEST_ONLINE:
        assert type(ticket_id) == str, "zs_create_ticket() should return a string with the ticket ID"
    else:
        assert ticket_id == -1, "zs_create_ticket() should return a string with the ticket ID (-1 if TEST_ONLINE is False))"

    # Print the results
    mlog = logging_helper.Log("test_znuny_otrs")
    mlog.info("Ticket ID:")
    mlog.info(ticket_id)

def test_add_note_to_ticket():
    TEST_ONLINE = False # Set to True to test the integration with changings to a real OTRS instance

    # Test "raw" note creation
    result = zs_add_note_to_ticket("2023052177000051", "raw", not TEST_ONLINE, "Test Note Title", "Test Note Body")
    if TEST_ONLINE:
        assert type(result) == int, "zs_add_note_to_ticket() should return an integer with the note ID"
    else:
        assert result == -1, "zs_add_note_to_ticket() should return a string with the note ID"
    # Print the results
    mlog = logging_helper.Log("test_znuny_otrs")
    mlog.info("Note ID:")
    mlog.info(result)


#test_zs_create_ticket()