# Z-SOAR
# Created by: Martin Offermann
# This module is a helper module that privides important classes and functions for the Z-SOAR project.

import random
import datetime
import socket
import datetime

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
        __init__(self, detections: list[Detection])
        __str__(self)
    """

    def __init__(self, detections: list[Detection]):
        """Initializes a new DetectionReport object."""
        self.detections = detections
        self.playbooks: list[str] = []
        self.action = None
        self.action_result = None
        self.action_result_message = None
        self.action_result_data = None
        self.contexts: list[Context] = []

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
    The SIEM  category type is used for context from the SIEM. It has three sub-categories: 'Events', 'Flows' and 'Processes'.  The ThreatIntel category type is used for context from
    threat intelligence sources. The ITSM category type is used for context from ITSM sources.

    Attributes:
        category (str): The category of the context
        sub_category (str): The sub-category of the context
        data (list[str]): The data of the context

    Methods:
        __init__(self)
        __str__(self)
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
        """Initializes a new ContextEvent object."""
        self.category = "SIEM"
        self.sub_category = "Events"
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


class ContextEvent(Context):
    """ContextEvent class."""

    def __init__(
        self,
        flow,
        application,
        certificate,
        dns_query,
        dns_response,
        dns_type,
        file_hash,
        file_name,
        http,
    ):
        pass


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
        process_dns (DNS): The DNS object of the process
        process_certificate (Certificate): The certificate object of the process
        process_http (HTTP): The HTTP object of the process
        process_flow (Flow): The flow object of the process
        process_parent (ContextProcess): The parent process object of the process
        process_children (list[ContextProcess]): The children processes of the process
        process_environment_variables (list[EnvironmentVariable]): The environment variables of the process
        process_arguments (list[Argument]): The arguments of the process
        process_modules (list[Module]): The modules of the process
        process_thread (list[Thread]): The threads of the process

    """

    def __init__(
        process_name: str,
        process_id: int,
        parent_process_name: str = "N/A",
        parent_process_id: int = 0,
        process_path: str = "",
    ):
        pass


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
