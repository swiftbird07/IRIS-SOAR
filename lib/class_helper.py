# Z-SOAR
# Created by: Martin Offermann
# This module is a helper module that privides important classes and functions for the Z-SOAR project.

from typing import Union
import random
import datetime
import socket
import datetime
import json

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper

# TODO: Implement all classes and functions used by zsoar_worker.py and its modules


class Rule:
    """Rule class. This class is used for storing rules.

    Attributes:
        id (str): The ID of the rule
        name (str): The name of the rule
        description (str): The description of the rule
        severity (int): The severity of the rule
        tags (list[str]): The tags of the rule
        raw (str): The raw rule
        created_at (datetime): The creation date of the rule
        updated_at (datetime): The last update date of the rule


    Methods:
        __init__(self, id: str, name: str, severity: int, description: str = None, tags: list[str] = None, raw: str = None, created_at: datetime = None, updated_at: datetime = None)
        __str__(self)
    """

    def __init__(
        self,
        id: str,
        name: str,
        severity: int,
        description: str = None,
        tags: list[str] = None,
        raw: str = None,
        created_at: datetime = None,
        updated_at: datetime = None,
    ):
        """Initializes a new Rule object."""
        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.tags = tags
        self.raw = raw
        self.created_at = created_at
        self.updated_at = updated_at

    def __str__(self):
        """Returns the string representation of the object."""
        return "Rule: " + self.name + " (" + self.id + ") with severity " + self.severity

    # Getter and setter;

    # ...


class Detection:
    """Detection class. This class is used for storing detections.

    Attributes:
        id (str): The ID of the detection
        name (str): The name of the detection
        rules (list[Rule]): The rules that triggered the detection
        description (str): The description of the detection
        tags (list[str]): The tags of the detection
        raw (str): The raw detection
        timestamp (datetime): The timestamp of the detection
        source (str): The source of the detection
        source_ip (socket.inet_aton): The source IP of the detection
        source_port (int): The source port of the detection
        destination (str): The destination of the detection
        destination_ip (datetime): The destination IP of the detection
        destination_port (int): The destination port of the detection
        protocol (str): The protocol of the detection
        severity (int): The severity of the detection
        process (ContextProcess): The process of the detection

    Methods:
        __init__(self, id: str, name: str, rules: list[Rule], description: str = None, tags: list[str] = None, raw: str = None, timestamp: datetime = None, source: str = None, source_ip: socket.inet_aton = None, source_port: int = None, destination: str = None, destination_ip: datetime = None, destination_port: int = None, protocol: str = None, severity: int = None, process: ContextProcess = None)
        __str__(self)
    """

    def __init__(
        self,
        id: str,
        name: str,
        rules: list[Rule],
        description: str = None,
        tags: list[str] = None,
        raw: str = None,
        timestamp: datetime = None,
        source: str = None,
        source_ip: socket.inet_aton = None,
        source_port: int = None,
        destination: str = None,
        destination_ip: datetime = None,
        destination_port: int = None,
        protocol: str = None,
        severity: int = None,
        process=None,  # Type: ContextProcess
    ):
        """Initializes a new Detection object."""
        self.id = id
        self.name = name
        self.description = description
        self.timestamp = timestamp
        self.source = source
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination = destination
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.severity = severity
        self.tags = tags
        self.raw = raw
        self.rules = rules
        self.process = process

    def __str__(self):
        """Returns the string representation of the object."""
        return (
            "Detection: "
            + self.name
            + " ("
            + self.id
            + ") from "
            + self.source
            + " ("
            + self.source_ip
            + ":"
            + self.source_port
            + ") to "
            + self.destination
            + " ("
            + self.destination_ip
            + ":"
            + self.destination_port
            + ") with protocol "
            + self.protocol
            + " and severity "
            + self.severity
        )

    # Getter and setter;

    # ...


class DetectionReport:
    """DetectionReport class. This class is used for storing detection reports.

    Attributes:
        detections (list[Detection]): The detections of the report
        playbooks (list[str]): The playbooks of the report
        action (str): The action of the report
        action_result (bool): The action result of the report
        action_result_message (str): The action result message of the report
        action_result_data (str): The action result data of the report
        contexts (list[Context]): The contexts of the report


    Methods:
        __init__(self, detections: list[Detection], playbooks: list[str] = None, action: str = None, action_result: bool = None, action_result_message: str = None, action_result_data: str = None, contexts: list[Context] = None): Initializes a new DetectionReport object.
        __str__(self): Returns the string representation of the object.
    """

    def __init__(self, detections: list[Detection]):
        """Initializes a new DetectionReport object."""
        self.detections = detections
        self.playbooks: list[str] = []
        self.action = None
        self.action_result = None
        self.action_result_message = None
        self.action_result_data = None
        self.context_logs: list[ContextLog] = []
        self.context_processes: list[ContextProcess] = []
        self.context_flows: list[ContextFlow] = []
        self.context_threat_intel: list[ContextThreatIntel] = []

    def __str__(self):
        """Returns the string representation of the object."""
        return (
            "DetectionReport: "
            + self.detection.name
            + " ("
            + self.detection.id
            + ") from "
            + self.detection.source
            + " ("
            + self.detection.source_ip
            + ":"
            + self.detection.source_port
            + ") to "
            + self.detection.destination
            + " ("
            + self.detection.destination_ip
            + ":"
            + self.detection.destination_port
            + ") with protocol "
            + self.detection.protocol
            + " and severity "
            + self.detection.severity
            + " was handled by playbook "
            + self.playbook
            + " with action "
            + self.action
            + " and result "
            + self.action_result
            + " ("
            + self.action_result_message
            + ")"
        )

    # Getter and setter;

    # ...


class Context:
    """This class provides a context for a detection. It has three main category types: "SIEM", "ThreatIntel" and "ITSM".
    The SIEM  category type is used for context from the SIEM. It has three sub-categories: 'logs', 'Flows' and 'Processes'.  The ThreatIntel category type is used for context from
    threat intelligence sources. The ITSM category type is used for context from ITSM sources.

    Attributes:
        category (str): The category of the context
        sub_category (str): The sub-category of the context
        data (list[str]): The data of the context

    Methods:
        __init__(self, category: str, sub_category: str, data: list[str]): Initializes a new Context object.
        __str__(self): Returns the string representation of the object.
    """

    def __init__(self):
        """Initializes a new Context object."""
        self.category = None
        self.sub_category = None
        self.data = []

    def __str__(self):
        """Returns the string representation of the object."""
        return "Context: " + self.category + " (" + self.sub_category + ") with data " + self.data

    # Getter and setter;

    # ...


class ContextFlow(Context):
    """This class provides a single context of type flow for a detection. It extends the Context class.

    Attributes:
        timestamp (datetime): The timestamp of the flow
        integration (str): The integration of the flow
        source_ip (socket.inet_aton): The source IP of the flow
        source_port (int): The source port of the flow
        destination_ip (socket.inet_aton): The destination IP of the flow
        destination_port (int): The destination port of the flow
        protocol (str): The protocol of the flow
        data (str): The data of the flow
        source_mac (socket.mac): The source MAC of the flow
        destination_mac (str): The destination MAC of the flow
        source_hostname (str): The source hostname of the flow
        destination_hostname (str): The destination hostname of the flow
        category (str): The category of the flow
        sub_category (str): The sub-category of the flow
        flow_direction (str): The flow direction of the flow
        flow_id (int): The flow ID of the flow
        interface (str): The interface of the flow
        network (str): The network of the flow
        network_type (str): The network type of the flow
        flow_source (str): The flow source of the flow

    Methods:
        __init__(self, timestamp: datetime.datetime, integration: str, source_ip: socket.inet_aton, source_port: int, destination_ip: socket.inet_aton, destination_port: int, protocol: str, data: str = None, source_mac: socket.mac = None, destination_mac: str = None, source_hostname: str = None, destination_hostname: str = None, category: str = "Generic Flow", sub_category: str = "Generic HTTP(S) Traffic", flow_direction: str = "L2R", flow_id: int = random.randint(1, 1000000000), interface: str = None, network: str = None, network_type: str = None, flow_source: str = None)
        __str__(self)
    """

    def __init__(
        self,
        timestamp: datetime.datetime,
        integration: str,
        source_ip: socket.inet_aton,
        source_port: int,
        destination_ip: socket.inet_aton,
        destination_port: int,
        protocol: str,
        data: str = None,
        source_mac: str = None,
        destination_mac: str = None,
        source_hostname: str = None,
        destination_hostname: str = None,
        category: str = "Generic Flow",
        sub_category: str = "Generic HTTP(S) Traffic",
        flow_direction: str = "L2R",
        flow_id: int = random.randint(1, 1000000000),
        interface: str = None,
        network: str = None,
        network_type: str = None,
        flow_source: str = None,
    ):
        """Initializes a new ContextFlow object."""
        self.category = "SIEM"
        self.sub_category = "Flow"
        self.data = []

        self.timestamp = timestamp
        self.data = data
        self.integration = integration

        self.source_ip = source_ip
        self.source_port = source_port

        self.destination_ip = destination_ip
        self.destination_port = destination_port

        self.protocol = protocol

        self.source_mac = source_mac
        self.destination_mac = destination_mac

        self.source_hostname = source_hostname
        self.destination_hostname = destination_hostname

        self.category = category
        self.sub_category = sub_category

        self.flow_direction = flow_direction
        self.flow_id = flow_id

        self.interface = interface
        self.network = network
        self.network_type = network_type
        self.flow_source = flow_source

    def __str__(self):
        """Returns the string representation of the object."""
        return (
            "ContextFlow: "
            + self.integration
            + " from "
            + self.source_ip
            + ":"
            + self.source_port
            + " to "
            + self.destination_ip
            + ":"
            + self.destination_port
            + " with protocol "
            + self.protocol
            + " Source MAC: "
            + self.source_mac
            + " Destination MAC: "
            + self.destination_mac
            + " Source Hostname: "
            + self.source_hostname
            + " Destination Hostname: "
            + self.destination_hostname
            + " Flow Direction: "
            + self.flow_direction
            + " Flow ID: "
            + self.flow_id
            + " Data "
            + self.data
            + " ( Category: "
            + self.category
            + " / "
            + self.sub_category
            + ")"
            + "Timestamp: "
            + self.timestamp
        )

    # Getter and setter;

    # ...


class Certificate:
    """Certificate class.

    Attributes:
        flow (ContextFlow): The flow of the certificate
        subject (str): The subject of the certificate
        issuer (str): The issuer of the certificate
        issuer_common_name (str): The issuer common name of the certificate
        issuer_organization (str): The issuer organization of the certificate
        issuer_organizational_unit (str): The issuer organizational unit of the certificate
        serial_number (str): The serial number of the certificate
        subject_common_name (str): The subject common name of the certificate
        subject_organization (str): The subject organization of the certificate
        subject_organizational_unit (str): The subject organizational unit of the certificate
        subject_alternative_name (str): The subject alternative name of the certificate
        valid_from (datetime): The valid from of the certificate
        valid_to (datetime): The valid to of the certificate
        version (str): The version of the certificate
        signature_algorithm (str): The signature algorithm of the certificate
        public_key_algorithm (str): The public key algorithm of the certificate
        public_key_size (int): The public key size of the certificate


    Methods:
        __init__(self, flow: ContextFlow, subject: str, issuer: str, issuer_common_name: str = None, issuer_organization: str = None, issuer_organizational_unit: str = None, serial_number: str = None, subject_common_name: str = None, subject_organization: str = None, subject_organizational_unit: str = None, subject_alternative_name: str = None, valid_from: datetime = None, valid_to: datetime = None, version: str = None, signature_algorithm: str = None, public_key_algorithm: str = None, public_key_size: int = None)
        __str__(self)
    """

    def __init__(
        self,
        flow: ContextFlow,
        subject: str,
        issuer: str,
        issuer_common_name: str = None,
        issuer_organization: str = None,
        issuer_organizational_unit: str = None,
        serial_number: str = None,
        subject_common_name: str = None,
        subject_organization: str = None,
        subject_organizational_unit: str = None,
        subject_alternative_name: str = None,
        valid_from: datetime = None,
        valid_to: datetime = None,
        version: str = None,
        signature_algorithm: str = None,
        public_key_algorithm: str = None,
        public_key_size: int = None,
    ):
        self.flow = flow
        self.issuer = issuer
        self.issuer_common_name = issuer_common_name
        self.issuer_organization = issuer_organization
        self.issuer_organizational_unit = issuer_organizational_unit
        self.serial_number = serial_number
        self.subject = subject
        self.subject_common_name = subject_common_name
        self.subject_organization = subject_organization
        self.subject_organizational_unit = subject_organizational_unit
        self.subject_alternative_name = subject_alternative_name
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.version = version
        self.signature_algorithm = signature_algorithm
        self.public_key_algorithm = public_key_algorithm
        self.public_key_size = public_key_size

    def __str__(self):
        return "Certificate: " + self.subject + " ( Issuer: " + self.issuer + " )"


class DNSQuery:
    """DNSQuery class.

    Attributes:
        flow (ContextFlow): The flow of the DNS query
        type (str): The type of the DNS query
        query (str): The query of the DNS query
        query_response (str): The query response of the DNS query
        rcode (str): The rcode of the DNS query

    Methods:
        __init__(self, flow: ContextFlow, type: str, query: str, query_response: str = None, rcode: str = "NOERROR")
        __str__(self)
    """

    def __init__(
        self,
        flow: ContextFlow,
        type: str,
        query: str,
        query_response: str = None,
        rcode: str = "NOERROR",
    ):
        self.flow = flow
        self.type = type
        self.query = query
        self.query_response = query_response
        self.rcode = rcode

    def __str__(self):
        return (
            "DNSQuery: "
            + self.query
            + " ( Type: "
            + self.type
            + " )"
            + " Response: "
            + self.query_response
            + " ( RCODE: "
            + self.rcode
            + " )"
        )


class HTTP:
    """HTTP class.

    Attributes:
        flow (ContextFlow): The flow of the HTTP request
        method (str): The method of the HTTP request
        type (str): The type of the HTTP request
        host (str): The host of the HTTP request
        path (str): The path of the HTTP request
        full_url (str): The full URL of the HTTP request
        user_agent (str): The user agent of the HTTP request
        referer (str): The referer of the HTTP request
        status_code (int): The status code of the HTTP request
        status_message (str): The status message of the HTTP request
        request_body (str): The request body of the HTTP request
        response_body (str): The response body of the HTTP request
        request_headers (str): The request headers of the HTTP request
        response_headers (str): The response headers of the HTTP request
        http_version (str): The HTTP version of the HTTP request

    Methods:
        __init__(self, flow: ContextFlow, method: str, type: str, host: str, path: str, full_url: str, user_agent: str, referer: str, status_code: int, status_message: str, request_body: str, response_body: str, request_headers: str, response_headers: str, http_version: str)
        __str__(self)
    """

    def __init__(
        self,
        flow: ContextFlow,
        method: str,
        type: str,
        host: str,
        path: str,
        full_url: str,
        user_agent: str,
        referer: str,
        status_code: int,
        status_message: str,
        request_body: str,
        response_body: str,
        request_headers: str,
        response_headers: str,
        http_version: str,
    ):
        self.flow = flow
        self.method = method
        self.type = type
        self.host = host
        self.path = path
        self.full_url = full_url
        self.user_agent = user_agent
        self.referer = referer
        self.status_code = status_code
        self.status_message = status_message
        self.request_body = request_body
        self.response_body = response_body
        self.request_headers = request_headers
        self.response_headers = response_headers
        self.http_version = http_version

    def __str__(self):
        return (
            "HTTP: "
            + self.method
            + " "
            + self.full_url
            + " ( Host: "
            + self.host
            + " )"
            + " Status: "
            + self.status_code
            + " "
            + self.status_message
            + " ( User-Agent: "
            + self.user_agent
            + " )"
        )


class ContextProcess(Context):
    """ContextProcess class.

    Attributes:
        process_name (str): The name of the process
        process_id (int): The ID of the process
        parent_process_name (str): The name of the parent process
        parent_process_id (int): The ID of the parent process
        process_path (str): The path of the process
        process_md5 (str): The MD5 hash of the process
        process_sha1 (str): The SHA1 hash of the process
        process_sha256 (str): The SHA256 hash of the process
        process_command_line (str): The command line of the process
        process_username (str): The username of the process
        process_integrity_level (str): The integrity level of the process
        process_is_elevated_token (bool): True if the process has an elevated token, False if not
        process_token_elevation_type (str): The token elevation type of the process
        process_token_elevation_type_full (str): The token elevation type of the process in full
        process_token_integrity_level (str): The token integrity level of the process
        process_token_integrity_level_full (str): The token integrity level of the process in full
        process_privileges (str): The privileges of the process
        process_owner (str): The owner of the process
        process_group_id (str): The group ID of the process
        process_group_name (str): The group name of the process
        process_logon_guid (str): The logon GUID of the process
        process_logon_id (str): The logon ID of the process
        process_logon_type (str): The logon type of the process
        process_logon_type_full (str): The logon type of the process in full
        process_logon_time (str): The logon time of the process
        process_start_time (str): The start time of the process
        process_parent_start_time (str): The start time of the parent process
        process_current_directory (str): The current directory of the process
        process_image_file_device (str): The image file device of the process
        process_image_file_directory (str): The image file directory of the process
        process_image_file_name (str): The image file name of the process
        process_image_file_path (str): The image file path of the process
        process_dns (DNSQuery): The DNS object of the process
        process_certificate (Certificate): The certificate object of the process
        process_http (HTTP): The HTTP object of the process
        process_flow (ContextFlow): The flow object of the process
        process_parent (ContextProcess): The parent process object of the process
        process_children (list[ContextProcess]): The children processes of the process
        process_environment_variables (list[]): The environment variables of the process
        process_arguments (list[]): The arguments of the process
        process_modules (list[]): The modules of the process
        process_thread (str): The threads of the process

    Methods:
        __init__(self, process_name: str, process_id: int, parent_process_name: str = "N/A", parent_process_id: int = 0, process_path: str = "", process_md5: str = "", process_sha1: str = "", process_sha256: str = "", process_command_line: str = "", process_username: str = "", process_integrity_level: str = "", process_is_elevated_token: bool = False, process_token_elevation_type: str = "", process_token_elevation_type_full: str = "", process_token_integrity_level: str = "", process_token_integrity_level_full: str = "", process_privileges: str = "", process_owner: str = "", process_group_id: str = "", process_group_name: str = "", process_logon_guid: str = "", process_logon_id: str = "", process_logon_type: str = "", process_logon_type_full: str = "", process_logon_time: str = "", process_start_time: str = "", process_parent_start_time: str = "", process_current_directory: str = "", process_image_file_device: str = "", process_image_file_directory: str = "", process_image_file_name: str = "", process_image_file_path: str = "", process_dns: DNSQuery = None, process_certificate: Certificate = None, process_http: HTTP = None, process_flow: ContextFlow = None, process_parent: ContextProcess = None, process_children: list[ContextProcess] = None, process_environment_variables: list[] = None, process_arguments: list[] = None, process_modules: list[] = None, process_thread: str = "")
        __str__(self)
    """

    def __init__(
        self,
        process_name: str,
        process_id: int,
        parent_process_name: str = "N/A",
        parent_process_id: int = 0,
        process_path: str = "",
        process_md5: str = "",
        process_sha1: str = "",
        process_sha256: str = "",
        process_command_line: str = "",
        process_username: str = "",
        process_integrity_level: str = "",
        process_is_elevated_token: bool = False,
        process_token_elevation_type: str = "",
        process_token_elevation_type_full: str = "",
        process_token_integrity_level: str = "",
        process_token_integrity_level_full: str = "",
        process_privileges: str = "",
        process_owner: str = "",
        process_group_id: str = "",
        process_group_name: str = "",
        process_logon_guid: str = "",
        process_logon_id: str = "",
        process_logon_type: str = "",
        process_logon_type_full: str = "",
        process_logon_time: str = "",
        process_start_time: str = "",
        process_parent_start_time: str = "",
        process_current_directory: str = "",
        process_image_file_device: str = "",
        process_image_file_directory: str = "",
        process_image_file_name: str = "",
        process_image_file_path: str = "",
        process_dns: DNSQuery = None,
        process_certificate: Certificate = None,
        process_http: HTTP = None,
        process_flow: ContextFlow = None,
        process_parent: list = None,
        process_children: list = None,
        process_environment_variables: list = None,
        process_arguments: list = None,
        process_modules: list = None,
        process_thread: str = None,
    ):
        self.process_name = process_name
        self.process_id = process_id
        self.parent_process_name = parent_process_name
        self.parent_process_id = parent_process_id
        self.process_path = process_path
        self.process_md5 = process_md5
        self.process_sha1 = process_sha1
        self.process_sha256 = process_sha256
        self.process_command_line = process_command_line
        self.process_username = process_username
        self.process_integrity_level = process_integrity_level
        self.process_is_elevated_token = process_is_elevated_token
        self.process_token_elevation_type = process_token_elevation_type
        self.process_token_elevation_type_full = process_token_elevation_type_full
        self.process_token_integrity_level = process_token_integrity_level
        self.process_token_integrity_level_full = process_token_integrity_level_full
        self.process_privileges = process_privileges
        self.process_owner = process_owner
        self.process_group_id = process_group_id
        self.process_group_name = process_group_name
        self.process_logon_guid = process_logon_guid
        self.process_logon_id = process_logon_id
        self.process_logon_type = process_logon_type
        self.process_logon_type_full = process_logon_type_full
        self.process_logon_time = process_logon_time
        self.process_start_time = process_start_time
        self.process_parent_start_time = process_parent_start_time
        self.process_current_directory = process_current_directory
        self.process_image_file_device = process_image_file_device
        self.process_image_file_directory = process_image_file_directory
        self.process_image_file_name = process_image_file_name
        self.process_image_file_path = process_image_file_path
        self.process_dns = process_dns
        self.process_certificate = process_certificate
        self.process_http = process_http
        self.process_flow = process_flow
        self.process_parent = process_parent
        self.process_children = process_children
        self.process_environment_variables = process_environment_variables
        self.process_arguments = process_arguments
        self.process_modules = process_modules
        self.process_thread = process_thread

    def __str__(self):
        try:
            return json.dumps(self.__dict__, indent=4)
        except:
            return self.process_name + " (" + str(self.process_id) + ")"


class ContextLog(Context):
    """The ContextLog class. Used for storing log data like syslog from a SIEM.

    Attrbutes:
        log_message (str): The message of the log
        log_source (str): The source of the log
        log_flow (ContextFlow): The flow object related to the log
        log_protocol (str): The protocol of the log
        log_timestamp (str): The timestamp of the log
        log_type (str): The type of the log
        log_severity (str): The severity of the log
        log_facility (str): The facility of the log
        log_tags (list[str]): The tags of the log
        log_custom_fields (dict): The custom fields of the log

    Methods:
        __init__(log_message, log_source, log_flow, log_protocol, log_timestamp, log_type, log_severity, log_facility, log_tags, log_custom_fields): Initializes the ContextLog object
        __str__(self): Returns the ContextLog object as a string

    """

    def __init__(
        self,
        log_message: str,
        log_source: str,
        log_flow: ContextFlow = None,
        log_protocol: str = "",
        log_timestamp: str = "",
        log_type: str = "",
        log_severity: str = "",
        log_facility: str = "",
        log_tags: list = None,
        log_custom_fields: dict = None,
    ):
        self.log_message = log_message
        self.log_source = log_source
        self.log_flow = log_flow
        self.log_protocol = log_protocol
        self.log_timestamp = log_timestamp
        self.log_type = log_type
        self.log_severity = log_severity
        self.log_facility = log_facility
        self.log_tags = log_tags
        self.log_custom_fields = log_custom_fields

    def __str__(self):
        try:
            return json.dumps(self.__dict__, indent=4)
        except:
            return self.log_message


class ThreatIntelDetection:
    """Detection by an idividual threat intel engine (e.g. Kaspersky, Avast, Microsoft, etc.).

    Attributes:
        engine (str): The name of the detection engine
        is_known (bool): If the indicator is known by the detection engine
        is_hit (bool): If the detection engine hit on the indicator
        hit_type (str): The type of the hit (e.g. malicious, suspicious, etc.)
        threat_name (str): The name of the threat (if available)
        confidence (int): The confidence of the detection engine (if available)
        engine_version (str): The version of the detection engine
        engine_update (datetime): The last update of the detection engine
    """

    def __init__(
        self,
        engine: str,
        is_known: bool,
        is_hit: bool = False,
        hit_type: str = "",
        threat_name: str = "",
        confidence: int = "",
        engine_version: str = "",
        engine_update: datetime = None,
    ):
        """Initializes a new ThreatIntelDetection object."""
        self.is_known = is_known
        self.is_hit = is_hit
        self.hit_type = hit_type
        self.threat_name = threat_name
        self.confidence = confidence
        self.engine = engine
        self.engine_version = engine_version
        self.engine_update = engine_update

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(self.__dict__, indent=4, sort_keys=True, default=str)


class ContextThreatIntel:
    """DetectionThreatIntel class. This class is used for storing threat intel (e.g. VirusTotal, AlienVault OTX, etc.).

    Attributes:
        type (type): The type of the indicator
        indicator(socket.intet_aton | HTTP | DNSQuery | ContextProcess ) The indicator
        score_hit (int): The hits on the particular indicator
        score_total (int): The total possible score of the indicator
        source (str): The integration source of the indicator
        timestamp (datetime): The timestamp of the lookup
        threat_intel_detections (list[ThreatIntelDetection]): The threat intel detections of the indicator

    Methods:
        __init__(type, indicator, score_hit, score_total, source, timestamp, threat_intel_detections): Initializes the ContextThreatIntel object
        __str__(self): Returns the ContextThreatIntel object as a string
    """

    def __init__(
        self,
        type: type,
        indicator: Union[socket.inet_aton, HTTP, DNSQuery, ContextProcess],
        score_hit: int,
        score_total: int,
        source: str,
        timestamp: datetime,
        threat_intel_detections: list[ThreatIntelDetection],
    ):
        """Initializes a new ContextThreatIntel object."""
        self.type = type
        self.indicator = indicator
        self.score_hit = score_hit
        self.score_total = score_total
        self.source = source
        self.timestamp = timestamp
        self.threat_intel_detections = threat_intel_detections

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(self.__dict__, indent=4, sort_keys=True, default=str)


def check_module_exists(module_name):
    """Checks if a module exists.

    Args:
        module_name (str): The name of the module

    Returns:
        bool: True if the module exists, False if not
    """
    try:
        __import__("integrations." + module_name)
        return True
    except ImportError:
        return False


def check_module_has_function(module_name, function_name, mlog):
    """Checks if a module has a function.

    Args:
        module_name (str): The name of the module
        function_name (str): The name of the function

    Returns:
        bool: True if the module has the function, False if not
    """
    try:
        module = __import__("integrations." + module_name)
        integration = getattr(module, module_name)
        getattr(integration, function_name)
        return True
    except AttributeError as e:
        mlog.debug("AttributeError: " + str(e))
        return False


def main():
    pass


if __name__ == "__main__":
    main()
