# Z-SOAR
# Created by: Martin Offermann
# This test module is used to test the zsoar.py module.
# It will test if the prvided arguments are working as expected.

import pytest
import zsoar
import datetime
import ipaddress
import uuid


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
    detection_report = class_helper.DetectionReport(detectionList)
    assert detection_report != None, "DetectionReport class could not be initialized"

    # Test ContextFlow class
    flow = class_helper.ContextFlow(
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
    cert = class_helper.Certificate(detection.uuid, "example.com", "Pytest Inc.", "Pytest CN", public_key_size=2048)
    assert cert != None, "Certificate class could not be initialized"

    # Test DNSQuery class
    dns_query = class_helper.DNSQuery(detection.uuid, "A", "www2.example.com", has_response=True, query_response="10.10.10.10")
    assert dns_query != None, "DNSQuery class could not be initialized"

    # Test HTTP class
    http = class_helper.HTTP(detection.uuid, "GET", "HTTPS", "www2.example.com", 200, path="index.html", user_agent="PyTest")
    assert http != None, "HTTP class could not be initialized"
    assert http.full_url == "https://www2.example.com/index.html", "HTTP class full_url not set correctly"

    # Test ContextProcess class
    parent_process = class_helper.ContextProcess(
        uuid.uuid4(), datetime.datetime.now(), detection.uuid, "word.exe", 242, "service.exe", 235, "C:\\Microsoft\word.exe"
    )
    assert parent_process != None, "ContextProcess class (for test parent) could not be initialized"

    process = class_helper.ContextProcess(
        uuid.uuid4(),
        datetime.datetime.now(),
        detection.uuid,
        "virus.exe",
        299,
        "word.exe",
        242,
        "C:\\Tmp\virus.exe",
        process_username="John Doe",
        process_md5="6f3b9dda23c69c097372ef91fd09420a",
        process_sha1="1234567890abcdef1234567890abcdef12345678",
        process_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        process_command_line="C:\\Microsoft\word.exe",
        process_parent=parent_process.process_uuid,
        is_complete=True,
    )
    assert process != None, "ContextProcessclass (for test child) could not be initialized"

    # Test ContextFile class
    file = class_helper.ContextFile(detection.uuid, datetime.datetime.now(), "delete", "image.png", "C:\\Tmp\image.png", 512456, is_directory=False, file_extension=".png")
    assert file != None, "File class could not be initialized"
    assert file.file_extension == "png", "File class file_extension not set correctly"

    # Test ContextLog class
    log_message = class_helper.ContextLog(
        detection.uuid,
        datetime.datetime.now(),
        "Failed user logon user=root",
        "Auth Logs @ Server",
        log_custom_fields={"Username": "root", "Account Name": "Something"},
        log_source_ip="10.12.0.1",
    )
    assert log_message != None, "ContextLog class could not be initialized"

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
        class_helper.ContextProcess, process, "VirusTotal", datetime.datetime.now(), ti_detections, score_hit=1, score_total=3
    )
    assert threat_intel != None, "ContextThreatIntel class could not be initialized (explicit score)"

    # Check if score is calculated correctly when not given explicitly
    threat_intel_impl_score = class_helper.ContextThreatIntel(
        class_helper.ContextProcess, process, "VirusTotal", datetime.datetime.now(), ti_detections, related_detection_uuid=detection.uuid
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
    device = class_helper.ContextDevice(
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

    # Test ContextRegistry class
    reg_context = class_helper.ContextRegistry(detection.uuid, datetime.datetime.now(), "modification", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "C:\\Windows\\System32\\calc.exe")
    assert reg_context.registry_key == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Could not create RegistryContext"
    assert reg_context.registry_value == "C:\\Windows\\System32\\calc.exe", "Could not create RegistryContext"

    # Test DetectionReport add_context
    detection_report.add_context(log_message)
    assert len(detection_report.context_logs) == 1, "Could not add context log_message to detection"
    assert detection_report.context_logs[0].log_message == "Failed user logon user=root", "Could not add log_message context to detection"

    detection_report.add_context(process)
    assert len(detection_report.context_processes) == 1, "Could not add process context to detection"
    assert detection_report.context_processes[0].process_name == "virus.exe", "Could not add process context to detection"

    detection_report.add_context(flow)
    assert detection_report.context_flows != None, "Could not add context flow to detection"
    assert len(detection_report.context_flows) == 1, "Could not add context flow to detection"
    assert str(detection_report.context_flows[0].source_ip) == "123.123.123.123", "Could not add context to detection"

    detection_report.add_context(threat_intel)
    assert len(detection_report.context_threat_intel) == 1, "Could not add threat_intel context to detection"
    assert detection_report.context_threat_intel[0].source == "VirusTotal", "Could not add threat_intel context to detection"

    detection_report.add_context(location)
    assert len(detection_report.context_locations) == 1, "Could not add location context to detection"
    assert detection_report.context_locations[0].country == "Germany", "Could not add location context to detection"

    detection_report.add_context(device)
    assert len(detection_report.context_devices) == 1, "Could not add device context to detection"
    assert detection_report.context_devices[0].name == "MacBook Pro von John Doe", "Could not add device context to detection"

    detection_report.add_context(person)
    assert len(detection_report.context_persons) == 1, "Could not add person context to detection"
    assert detection_report.context_persons[0].name == "John Doe", "Could not add person context to detection"

    detection_report.add_context(file)
    assert len(detection_report.context_files) == 1, "Could not add file context to detection"
    assert detection_report.context_files[0].file_name == "image.png", "Could not add file context to detection"

    flow.http = http
    detection_report.add_context(flow)
    assert type(detection_report.context_flows[0].http) == class_helper.HTTP, "Could not add http context to detection"
    assert detection_report.context_flows[0].http.method == "GET", "Could not add http context to detection"

    flow.dns_query = dns_query
    detection_report.add_context(flow)
    assert type(detection_report.context_flows[0].dns_query) == class_helper.DNSQuery, "Could not add dns_query context to detection"
    assert detection_report.context_flows[0].dns_query.query == "www2.example.com", "Could not add dns_query context to detection"

    flow.http.certificate = cert
    detection_report.add_context(flow)
    assert type(detection_report.context_flows[0].http.certificate) == class_helper.Certificate, "Could not add cert context to detection"
    assert detection_report.context_flows[0].http.certificate.subject == "example.com", "Could not add cert context to detection"

    assert detection_report.indicators is not None, "Could not add indicators to detection"
    assert len(detection_report.indicators) != 0, "Could not add indicators to detection"
    assert detection_report.indicators["ip"][0] == ipaddress.IPv4Address("123.123.123.123"), "Could not add indicators to detection"
    assert detection_report.indicators["domain"][0] == "www2.example.com", "Could not add indicators to detection"
    assert detection_report.indicators["url"][0] == "https://www2.example.com/index.html", "Could not add indicators to detection"
    assert detection_report.indicators["hash"][0] == "6f3b9dda23c69c097372ef91fd09420a", "Could not add indicators to detection"

    detection_report.add_context(flow)
    detection_report.add_context(flow)
    detection_report.add_context(flow)
    assert len(detection_report.indicators["url"]) == 1, "De-doubling of context objects failed"

    # Check DetectionReport add_context - timieline sorting and wildcard removal
    t1 = datetime.datetime.now()
    t2 = datetime.datetime.now() + datetime.timedelta(minutes=1)
    t3 = datetime.datetime.now() + datetime.timedelta(minutes=2)
    log_message1 = class_helper.ContextLog(
        detection.uuid,
        t3,
        "First created Log message. Happened last.",
        "Auth Logs @ Server",
        log_source_ip="1.1.1.1",
    )
    log_message2 = class_helper.ContextLog(
        detection.uuid, t1, "Second created Log message. Happened first.", "Auth Logs @ Server", log_source_ip="1.1.1.1"
    )
    log_message3 = class_helper.ContextLog(
        detection.uuid, t2, "Third created Log message. Happened in the middle.", "Auth Logs @ Server", log_source_ip="10.12.0.1"
    )
    detection_report.add_context(log_message1)
    detection_report.add_context(log_message2)
    detection_report.add_context(log_message3)
    assert len(detection_report.context_logs) == 1 + 3, "Could not add log messages to detection"
    assert detection_report.context_logs[1 + 0].log_message == "Second created Log message. Happened first.", "Time sorting of log messages failed"
    assert detection_report.context_logs[1 + 1].log_message == "Third created Log message. Happened in the middle.", "Time sorting of log msg failed"
    assert detection_report.context_logs[1 + 2].log_message == "First created Log message. Happened last.", "Time sorting of log messages failed"

    flow.dns_query = class_helper.DNSQuery(detection.uuid, "A", "*.example.com", True, "10.10.10.10")
    detection_report.add_context(flow)
    assert detection_report.indicators["domain"][1] == "example.com", "Could not add indicators to detection"
    
    detection_report.add_context(reg_context)
    assert detection_report.indicators["registry"][0] == "hklm\\software\\microsoft\\windows\\currentversion\\run->c:\\windows\\system32\\calc.exe", "Could not add indicators to detection"

    # Test DetectionReport class indicators
    detection_report2 = class_helper.DetectionReport(detection.uuid)
    detection_report2.add_context(flow)
    detection_report2.add_context(process)

    assert detection_report2.indicators is not None, "Could not add indicators to detection"
    assert len(detection_report2.indicators) != 0, "Could not add indicators to detection"
    assert detection_report2.indicators["ip"][0] == ipaddress.IPv4Address("123.123.123.123"), "Could not add indicators to detection"
    assert detection_report2.indicators["domain"][0] == "www2.example.com", "Could not add indicators to detection"
    assert detection_report2.indicators["url"][0] == "https://www2.example.com/index.html", "Could not add indicators to detection"
    assert detection_report2.indicators["hash"][0] == "6f3b9dda23c69c097372ef91fd09420a", "Could not add indicators to detection"
    
    # Test Detection class indicators
    detection2 = class_helper.Detection("Roman Bellic Enterprises", "Yet another detection", ruleList, datetime.datetime.now(), description="This is another test detection", process=process, flow=flow)
    assert detection2.indicators is not None, "Could not add indicators to detection"
    assert len(detection2.indicators) != 0, "Could not add indicators to detection"
    assert detection2.indicators["ip"][0] == ipaddress.IPv4Address("123.123.123.123"), "Could not add indicators to detection"
    assert detection2.indicators["domain"][0] == "www2.example.com", "Could not add indicators to detection"
    assert detection2.indicators["url"][0] == "https://www2.example.com/index.html", "Could not add indicators to detection"
    assert detection2.indicators["hash"][0] == "6f3b9dda23c69c097372ef91fd09420a", "Could not add indicators to detection"
    detection_report.detections.append(detection2)

    # Test auditLog class
    len_audit = len(detection_report.audit_trail)
    audit_log = class_helper.AuditLog("test", 0, "Test auditLog", "Testing the auditLog")
    assert audit_log.playbook == "test", "Could not create auditLog"

    audit_log.set_successful()
    assert audit_log.result_had_errors is False, "Could not set auditLog to successful"

    detection_report.update_audit(audit_log)
    assert len(detection_report.audit_trail) == len_audit + 1, "Could not add auditLog to DetectionReport"

    audit_log.set_error()
    assert audit_log.result_had_errors is True, "Could not set auditLog to failed"

    detection_report.update_audit(audit_log)
    assert len(detection_report.audit_trail) == len_audit + 1, "audit was overwritten"

    assert detection_report.get_audit_by_playbook("test")[0] == audit_log, "Could not get auditLog by playbook name"
    assert detection_report.get_audit_by_playbook_stage("test", 0)[0]== audit_log, "Could not get auditLog by playbook name and stage"
    assert detection_report.get_audit_by_playbook("test")[0].result_had_errors is True, "ActionLog was not updated with error"


    # Test String printings
    mlog.info("Test for printing objects: ")
    mlog.info("Rule: ")
    mlog.info(rule)
    mlog.info("Flow: ")
    mlog.info(str(flow))
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
    mlog.info("DETECTION REPORT: ")
    mlog.info(detection_report)
    mlog.info("DNS QUERY: ")
    mlog.info(dns_query)
    mlog.info("CERT: ")
    mlog.info(cert)
    mlog.info("LOG MESSAGE: ")
    mlog.info(log_message)
    mlog.info("INDICATORS: ")
    mlog.info(detection_report.indicators)
    mlog.info("Test for printing objects done.")

    # Test classes - Negative tests

    # TODO: Add negative tests

    return detection_report

def test_generic_helper():
    import lib.generic_helper as generic_helper
    
    generic_helper.add_to_cache("test", "entities", "123", "4566")
    generic_helper.get_from_cache("test", "entities", "123") == "4566", "Could not get from cache"
    # TODO: Add more tests

test_generic_helper()