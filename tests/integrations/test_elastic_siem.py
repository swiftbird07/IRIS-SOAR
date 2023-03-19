# Tests the Elastic SIEM integration

import pytest

from lib.class_helper import Detection, DetectionReport
from integrations.elastic_siem import zs_provide_new_detections, zs_provide_context_for_detections


def test_zs_provide_new_detections():
    detectionArray = zs_provide_new_detections(test=True)
    assert (
        type(detectionArray) == list
    ), "zs_provide_new_detections() should return a list of Detection objects"
    for detection in detectionArray:
        assert (
            type(detection) == Detection
        ), "zs_provide_new_detections() found an invalid Detection object in the list"


def test_zs_provide_context_for_detections():
    detectionReport = DetectionReport()
    detectionReport.id = "1234567890"
    detectionReport.name = "Test detection"
    detectionReport.description = "This is a test detection"
    detectionReport.timestamp = "2021-01-01 00:00:00"
    detectionReport.source = "Test source"
    detectionReport.source_ip = ""

    detectionReport = zs_provide_context_for_detections(detectionReport, test=True)
    assert (
        type(detectionReport) == DetectionReport
    ), "zs_provide_context_for_detections() should return a DetectionReport object"
