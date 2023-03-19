# Integration for Z-SOAR
# Created by: Martin Offermann
# This integration is for getting new detections from Elastic SIEM, and also provides context for detections.

import os
import sys
import time

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import lib.class_helper as class_helper  # TODO: Implement class_helper.py

# from elasticsearch import Elasticsearch


def main(config, fromDaemon=False):
    pass


def zs_provide_new_detections(test=False) -> class_helper.Detection:
    detections = []
    return detections


def zs_provide_context_for_detections(detectionReport, test=False) -> class_helper.DetectionReport:
    pass
