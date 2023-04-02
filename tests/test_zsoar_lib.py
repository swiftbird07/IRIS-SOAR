# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the zsoar.py module.
# It will test if the prvided arguments are working as expected.

import pytest
import zsoar
import datetime
import ipaddress


def test_logger():
    """Tests the logger helper function.

    Args:
        None

    Returns:
        None
    """
    try:
        mlog = zsoar.logging_helper.Log("test_zsoar_lib", log_level_stdout="INFO")
        mlog.info("Test message")
    except AttributeError as e:
        pytest.fail("The logger could not be initialized: {}".format(e))
    except Exception as e:
        pytest.fail("The logger could not be used: {}".format(e))


def test_config_loading():
    """Tests the config loading function and its validation.

    Args:
        None

    Returns:
        None
    """
    try:
        configObj = zsoar.config_helper.Config()
        cfg = configObj.cfg
    except Exception as e:
        pytest.fail("The config could not be loaded: {}".format(e))

    try:
        daemon_enabled = cfg["daemon"]["enabled"]  # Sample config value
        if daemon_enabled in [True, False]:
            pass
        else:
            pytest.fail(f"The config was loaded, but is misconfigured: cfg['daemon']['enabled'] not True or False: {daemon_enabled}")
    except Exception as e:
        pytest.fail(f"The config was loaded, but is empty: {cfg}. {e}")

    # Test that invalid values are detected
    mlog = zsoar.logging_helper.Log("test_zsoar_lib")
    cfg["logging"]["log_level_file"] = "some_invalid_value"
    assert zsoar.config_helper.check_config(cfg, mlog) == False, "The config is valid, but should not be (Value test)."

    # Reset the config
    cfg["logging"]["log_level_file"] = "debug"
    assert zsoar.config_helper.check_config(cfg, mlog) == True, "The config is not valid after resetting."

    # Test if invalid types are detected
    cfg["logging"]["log_level_stdout"] = True
    assert zsoar.config_helper.check_config(cfg, mlog) == False, "The config is valid, but should not be (Type test)."


def test_config_saving():
    """Tests the config saving function.

    Args:
        None

    Returns:
        None
    """
    configObj = zsoar.config_helper.Config()
    cfg = configObj.cfg
    assert zsoar.config_helper.save_config(cfg) == True, "Saving current config to file failed"
    tmp = cfg["logging"]["log_level_file"]

    cfg["logging"]["log_level_file"] = "some_invalid_value"
    assert zsoar.config_helper.save_config(cfg) == False, "Saving invalid config to file did not fail"

    cfg["logging"]["log_level_file"] = "debug"
    assert zsoar.config_helper.save_config(cfg) == True, "Saving valid new config to file failed"

    # Reset
    cfg["logging"]["log_level_file"] = tmp
    assert zsoar.config_helper.save_config(cfg) == True, "Saving valid old config to file failed"


def test_class_helper():
    """Tests the class helper function.

    Args:
        None

    Returns:
        None
    """
    mlog = zsoar.logging_helper.Log("test_zsoar_lib")
    import lib.class_helper as class_helper

    # Test classes - Postivie tests #

    # Test Rule class
    rule = class_helper.Rule("123", "Some Rule", 0)
    assert rule != None, "Rule class could not be initialized"

    ruleList = []
    ruleList.append(rule)

    # Test Detection class
    detection = class_helper.Detection("456", "Some Detection", ruleList, datetime.datetime.now())
    assert detection != None, "Detection class could not be initialized"

    detectionList = []
    detectionList.append(detection)

    # Test DetectionReport class
    assert class_helper.DetectionReport(detectionList) != None, "DetectionReport class could not be initialized"

    # Test Context class
    assert class_helper.Context("SIEM") != None, "Context class could not be initialized"

    # Test NetworkFlow class
    flow = class_helper.NetworkFlow(
        detection.uuid,
        datetime.datetime.now(),
        "PyTest",
        ipaddress.ip_address("123.123.123.123"),
        12345,
        "10.0.0.1",
        80,
        "TCP",
        application="HTTP",
        data="Some data",
        source_mac="00:00:00:00:00:00",
        destination_mac="00:00:00:00:00:00",
        source_hostname="PyTest",
        destination_hostname="Some Host",
        category="Test Flow",
        sub_category="PyTest",
        interface="eth0",
        network="WAN Network",
        network_type="WAN",
        flow_source="PyTest",
    )
    assert flow != None, "ContextFlow class could not be initialized"
    assert type(flow.source_ip) == ipaddress.IPv4Address, "ContextFlow initialized wrong ip type"
    assert flow.destination_ip == ipaddress.ip_address("10.0.0.1"), "ContextFlow initialized wrong ip value"
    assert flow.flow_direction == "R2L", "ContextFlow wrong flow direction calculation"
    assert flow.flow_id > 0, "ContextFlow id is not set"

    # Test Certificate class
    assert (
        class_helper.Certificate(flow, "example.com", "Pytest Inc.", "Pytest CN", public_key_size=2048) != None
    ), "Certificate class could not be initialized"

    # Test DNSQuery class
    assert (
        class_helper.DNSQuery(detection.uuid, flow, "A", "www2.example.com", has_response=True, query_response="10.10.10.10") != None
    ), "DNSQuery class could not be initialized"

    # Test HTTP class
    http = class_helper.HTTP(detection.uuid, flow, "GET", "HTTPS", "www2.example.com", 200, path="index.html", user_agent="PyTest")
    assert http != None, "HTTP class could not be initialized"
    assert http.full_url == "https://www2.example.com/index.html", "HTTP class full_url not set correctly"

    # Test Process class
    parent_process = class_helper.Process(detection.uuid, "word.exe", 242, "service.exe", 235, "C:\\Microsoft\word.exe")
    assert parent_process != None, "ContextProcess class (for test parent) could not be initialized"

    parents = []
    parents.append(parent_process)
    process = class_helper.Process(
        detection.uuid,
        "virus.exe",
        299,
        "word.exe",
        242,
        "C:\\Tmp\virus.exe",
        process_username="John Doe",
        process_md5="1234567890abcdef1234567890abcdef",
        process_sha1="1234567890abcdef1234567890abcdef12345678",
        process_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        process_command_line="C:\\Microsoft\word.exe",
        process_parents=parents,
    )
    assert process != None, "ContextProcessclass (for test child) could not be initialized"

    # Test File class
    file = class_helper.File("image.png", "C:\\Tmp\image.png", 512456, is_directory=False, file_extension=".png")
    assert file != None, "File class could not be initialized"
    assert file.file_extension == "png", "File class file_extension not set correctly"

    # Test LogMessage class
    assert (
        class_helper.LogMessage(
            datetime.datetime.now(),
            "Failed user logon user=root",
            "Auth Logs @ Server",
            flow,
            log_custom_fields={"Username": "root", "Account Name": "Something"},
        )
        != None
    ), "ContextLog class could not be initialized"

    # Test ThreatIntel class
    ti_detections = []
    test_hit = class_helper.ThreatIntel(datetime.datetime.now(), "Microsoft Defender", True, True, "Malicious", "GenVirus Trojan/32")
    assert test_hit != None, "ThreatIntelDetection class could not be initialized (test hit)"

    test_unknwon = class_helper.ThreatIntel(datetime.datetime.now(), "Avast", False)
    assert test_unknwon != None, "ThreatIntelDetection class could not be initialized (test unknown)"

    test_clean = class_helper.ThreatIntel(datetime.datetime.now(), "Kaspersky", True, False)
    assert test_clean != None, "ThreatIntelDetection class could not be initialized (test clean)"

    ti_detections.append(test_hit)
    ti_detections.append(test_unknwon)
    ti_detections.append(test_clean)

    # Test ContextThreatIntel class
    threat_intel = class_helper.ContextThreatIntel(
        class_helper.Process, process, "VirusTotal", datetime.datetime.now(), ti_detections, score_hit=1, score_total=3
    )
    assert threat_intel != None, "ContextThreatIntel class could not be initialized (explicit score)"

    # Check if score is calculated correctly when not given explicitly
    threat_intel_impl_score = class_helper.ContextThreatIntel(
        class_helper.Process, process, "VirusTotal", datetime.datetime.now(), ti_detections, related_detection_uuid=detection.uuid
    )
    assert threat_intel_impl_score != None, "ContextThreatIntel class could not be initialized (implicit score)"
    assert threat_intel_impl_score.score_hit == 1, "ContextThreatIntel class score_hit not calculated correctly"
    assert threat_intel_impl_score.score_known == 2, "ContextThreatIntel class score_known not calculated correctly"
    assert threat_intel_impl_score.score_total == 3, "ContextThreatIntel class score_total not calculated correctly"

    # Test Location class
    location = class_helper.Location(
        "Germany", "Berlin", -13.0, 52.0, "Europe/Berlin", "AS/295", "Microsoft", "Microsoft Corp.", 85, datetime.datetime.now()
    )
    assert location != None, "Location class could not be initialized"

    # Test Vulnerability class
    vulnerability = class_helper.Vulnerability(
        "CVE-2020-1234",
        "A very bad vulnerability",
        "https://example.com/vuln",
        datetime.datetime.now(),
        patched_at=datetime.datetime.now(),
        attack_complexity="Low",
        attack_vector="Network",
        availability_impact="High",
        confidentiality_impact="High",
        integrity_impact="High",
        privileges_required="None",
        scope="Unchanged",
        user_interaction="None",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        version="3.1",
        updated_at=datetime.datetime.now(),
    )
    assert vulnerability != None, "Vulnerability class could not be initialized"
    assert vulnerability.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Vulnerability class cvss_vector not set correctly"
    assert vulnerability.version == "3.1", "Vulnerability class cvss_version not set correctly"
    assert vulnerability.user_interaction == "None", "Vulnerability class user_interaction not set correctly"
    assert type(vulnerability.updated_at) == datetime.datetime, "Vulnerability class updated_at not set correctly"

    # Test Service class
    service = class_helper.Service(
        "Microsoft Exchange",
        "Microsoft",
        tags=["Exchange", "Microsoft"],
        latest_version="2016",
        ports=[443, 25],
        protocol="HTTPS",
        risk_score=12,
        child_services=[],
    )
    assert service != None, "Service class could not be initialized"
    service.child_services.append(class_helper.Service("SSH", "-", tags=["SSH", "Authentication"], ports=[22], protocol="TCP"))
    service.child_services.append(class_helper.Service("HTTP", "-", tags=["HTTP", "Web"], ports=[80], protocol="TCP"))
    assert len(service.child_services) == 2, "Service class child_services not set correctly"

    # Test Person class
    person = class_helper.Person(
        "John Doe", "mail@doe.com", "1234567890", tags=["John", "Doe"], access_to=[service], roles=["Admin"], primary_location=location
    )
    assert person != None, "Person class could not be initialized"
    assert len(person.access_to) == 1, "Person class access_to not set correctly"
    assert len(person.roles) == 1, "Person class roles not set correctly"

    # Test Device class
    device = class_helper.Device(
        "MacBook Pro von John Doe",
        "10.12.2.4",
        mac="00:00:00:00:00:00",
        tags=["MacBook", "John", "Doe"],
        os="macOS",
        os_version="10.15.7",
        location=location,
        services=[service],
    )
    assert device != None, "Device class could not be initialized"
    assert len(device.services) == 1, "Device class services not set correctly"
    assert device.services[0].name == "Microsoft Exchange", "Device class services not set correctly"

    # Test String printings
    mlog.info("Test for printing objects: ")
    mlog.info("Rule: ")
    mlog.info(rule)
    mlog.info("Flow: ")
    mlog.info(flow)
    mlog.info("HTTP: ")
    mlog.info(http)
    mlog.info("PROCESS 1: ")
    mlog.info(parent_process)
    mlog.info("PROCESS 2: ")
    mlog.info(process)
    mlog.info("FILE: ")
    mlog.info(file)
    mlog.info("TEST_HIT: ")
    mlog.info(test_hit)
    mlog.info("TEST_UNKNWON: ")
    mlog.info(test_unknwon)
    mlog.info("TEST_CLEAN: ")
    mlog.info(test_clean)
    mlog.info("THREAT INTEL: ")
    mlog.info(threat_intel)
    mlog.info("THREAT INTEL IMPL SCORE: ")
    mlog.info(threat_intel_impl_score)
    mlog.info("LOCATION: ")
    mlog.info(location)
    mlog.info("VULNERABILITY: ")
    mlog.info(vulnerability)
    mlog.info("SERVICE: ")
    mlog.info(service)
    mlog.info("PERSON: ")
    mlog.info(person)
    mlog.info("DEVICE: ")
    mlog.info(device)
    mlog.info("Test for printing objects done.")

    # Test classes - Negative tests

    # TODO: Add negative tests
