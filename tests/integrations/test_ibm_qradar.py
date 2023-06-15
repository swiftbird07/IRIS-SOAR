# Tests the IBM QRadar integration

import pytest

from lib.class_helper import Detection, DetectionReport, Rule, ContextProcess, ContextLog, ContextFlow
from integrations.ibm_qradar import zs_provide_new_detections
import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import datetime
import uuid


def test_zs_provide_new_detections():
    # Prepare the config
    cfg = config_helper.Config().cfg
    integration_config = cfg["integrations"]["ibm_qradar"]

    detectionArray = zs_provide_new_detections(integration_config, TEST="")
    assert type(detectionArray) == list, "zs_provide_new_detections() should return a list of Detection objects"
    for detection in detectionArray:
        assert type(detection) == Detection, "zs_provide_new_detections() found an invalid Detection object in the list"

