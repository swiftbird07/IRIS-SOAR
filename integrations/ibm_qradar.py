# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with IBM QRadar.
#
# This module is capable of:
# [ ] Providing new detections.
# [ ] Providing context for detections of type [ContextFlow | ContextLog]
# [ ] User interactive setup.
#
# Integration Version: 0.0.2
# Currently limited to process related detections and contexts.

from typing import Union, List
import datetime
import socket
import requests
from ssl import create_default_context
import sys
import json
import abc
import json
import time

import datetime
import json
import traceback
import dateutil.tz
import requests
import collections
import ipaddress

import lib.logging_helper as logging_helper

# For new detections:
from lib.class_helper import Rule, Detection, ContextFlow, ContextDevice, ContextLog, HTTP, ContextFile, ContextDevice, DNSQuery
from lib.config_helper import Config
from lib.generic_helper import cast_to_ipaddress

# For context for detections:
from lib.class_helper import (
    DetectionReport,
    ContextFlow,
    ContextLog,
)
from lib.generic_helper import dict_get, get_from_cache, add_to_cache, default

SEARCH_POLLING_INTERVAL = 1  # The interval in seconds to poll for the results of a QRadar search
MAX_RESULTS_QRADAR_SEARCH = 5000  # The maximum number of results that can be returned by a QRadar search
MAX_TRIES_QRADAR_SEARCH = 360  # The maximum number of tries to get the results of a QRadar search before giving up (time in seconds = MAX_TRIES_QRADAR_SEARCH * SEARCH_POLLING_INTERVAL)
CONNECTION_TIMEOUT = 3  # The timeout in seconds for the connection to QRadar (set higher if you have a slow connection)

# This is a query used to gather an AQL query for custom fields for a specified log source.
# Feel free to edit this log sources or custom fields to match your environment.
QUERIES = {
    "https://10.20.1.1": {
        "Suricata Traffic": {
            "SELECT": (
                "DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS 'Log Source Time'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "sourceport AS 'Source Port'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "destinationip AS 'Destination IP'",
                "destinationport AS 'Destination Port'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "username AS 'Username'",
                '"Application"',
                '"Certificate - Issuer"',
                '"Certificate - Subject"',
                '"DNS - Query"',
                '"DNS - Query Response"',
                '"DNS - Type"',
                '"Destination Host Name"',
                '"File Hash"',
                '"Filename"',
                '"HTTP - Content Type"',
                '"HTTP - Hostname"',
                '"HTTP - Method"',
                '"HTTP - Protocol"',
                '"HTTP - Status"',
                '"HTTP - URL"',
                '"HTTP - User Agent"',
                '"HTTP - Referer"',
                '"HTTP - Request Body"',
                '"HTTP - Request Headers"',
                '"HTTP - Response Body"',
                '"HTTP - Response Headers"',
                '"HTTP - Version"',
                '"Server Name Indication"',
            ),
            "FROM": "events",
            "WHERE": ("LOGSOURCENAME(logsourceid) MATCHES 'Suricata .*'",),
            "ORDER BY": ("devicetime ASC",),
        },
        "Firewall": {
            "SELECT": (
                "DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS 'Log Source Time'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "sourceport AS 'Source Port'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "destinationip AS 'Destination IP'",
                "destinationport AS 'Destination Port'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "username AS 'Username'",
                '"Firewall - Rule ID"',
            ),
            "FROM": "events",
            "WHERE": ("LOGSOURCENAME(logsourceid) MATCHES 'Firewall.*'",),
            "ORDER BY": ("devicetime ASC",),
        },
        "Suricata Alerts": {
            "SELECT": (
                "DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS 'Log Source Time'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "sourceport AS 'Source Port'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "destinationip AS 'Destination IP'",
                "destinationport AS 'Destination Port'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "username AS 'Username'",
                '"Alert - Created"',
                '"Alert - Action"',
                '"Alert - Category"',
                '"Alert - Domain"',
                '"Alert - SID"',
                '"Alert - Severity"',
                '"Alert - Signature"',
                '"Alert - Updated"',
            ),
            "FROM": "events",
            "WHERE": ("LOGSOURCENAME(logsourceid) MATCHES 'Suricata .*'",),
            "ORDER BY": ("devicetime ASC",),
        },
        "FALLBACK": {
            "SELECT": (
                "DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS 'Log Source Time'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "sourceport AS 'Source Port'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "destinationip AS 'Destination IP'",
                "destinationport AS 'Destination Port'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "username AS 'Username'",
            ),
            "FROM": "events",
            "WHERE": ("LOGSOURCENAME(logsourceid) MATCHES '.*'",),
            "ORDER BY": ("devicetime ASC",),
        },
    }
}
# Define what Log Sources are for what purpose of context:
FLOW_LOG_SOURCES = ["Firewall", "Suricata Traffic"]
LOG_LOG_SOURCES = ["Suricata Alerts", "FALLBACK"]
FILE_LOG_SOURCES = ["Suricata Traffic"]


if __name__ == "__main__":
    sys.exit()  # TODO: Add interactive setup


# Classses useful for QRadar:
class Client(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __init__(self, host, mlog, api_key, verify: bool = False):
        self.host = host

        if not verify:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        self.session.headers["Version"] = "12"
        self.session.verify = verify
        self.mlog = mlog

    def request(self, method: str, params: dict = None, path: str = None, url=None, timeout=CONNECTION_TIMEOUT):
        if path is not None and url is not None:
            raise ValueError("At least one of path or url must be None")

        assert method in ("GET", "POST", "DELETE")
        response = self.session.request(
            method=method,
            url=self.host + path if url is None else url,
            params=params,
            timeout=timeout,
        )
        return response

    def __del__(self):
        self.session.close()


class CredentialClient(Client):
    def __init__(self, host, username, password, verify: bool = False):
        super().__init__(host, verify)
        self.session.auth = (username, password)


class TokenClient(Client):
    def __init__(self, host, token, mlog, verify: bool = False):
        super().__init__(host, mlog, token, verify)
        self.session.headers["SEC"] = token


# Other useful functions:
def format_aql(query, offense, start, stop):
    aql = ""
    # SELECT
    aql += "SELECT {:s}\n".format(", ".join(query["SELECT"]) if "SELECT" in query else "*")
    # FROM
    aql += "FROM {:s}\n".format(query["FROM"] if "FROM" in query else "events")

    # WHERE
    if offense:
        where = ["INOFFENSE({:d})".format(offense)]
        if "WHERE" in query:
            where += query["WHERE"]
        aql += "WHERE {:s}\n".format(" AND ".join(where))
    else:
        raise NotImplementedError("No WHERE clause implemented for offense = None")  # TODO: Implement other AQL queries

    # GROUP BY
    if "GROUP BY" in query:
        aql += "GROUP BY {:s}\n".format(", ".join(query["GROUP BY"]))
    # ORDER BY
    if "ORDER BY" in query:
        aql += "ORDER BY {:s}\n".format(", ".join(query["ORDER BY"]))
    # START
    aql += "START {:d}\n".format(start - 1)
    # STOP
    aql += "STOP {:d}".format(stop + 1)
    return aql


def check(c, str):
    try:
        if c == "None" or c == "NoneNone":
            return str
        if not c in str:
            return str + "<br>" + c
        else:
            return str
    except:
        return str


def init_logging(config):
    """Initializes the logging for this module.

    Args:
        config (dict): The configuration dictionary for this integration

    Returns:
        logging_helper.Log: The logging object
    """
    log_level_file = config["logging"][
        "log_level_file"
    ]  # be aware that only configs from this integration are available not the general config
    log_level_stdout = config["logging"]["log_level_stdout"]
    log_level_syslog = config["logging"]["log_level_syslog"]

    mlog = logging_helper.Log(__name__, log_level_stdout=log_level_stdout, log_level_file=log_level_file)
    return mlog


class QRadar:
    def __init__(self, config_url, config_api_key, verify, mlog):
        self.client = TokenClient(config_url, config_api_key, mlog, verify)

    def get_offenses(self):
        fields = [
            "id",
            "description",
            "start_time",
            "rules",
            "categories",
            "credibility",
            "device_count",
            "log_sources",
            "magnitude",
            "offense_source",
            "relevance",
            "severity",
            "follow_up",
        ]
        params = {
            "fields": ",".join(fields),
            "filter": "status = OPEN and follow_up = False",
            "sort": "+id",
        }
        try:
            offenses = self.client.request(
                method="GET",
                path="/api/siem/offenses",
                params=params,
            )
        except requests.exceptions.RequestException as e:
            print(str(e))
            self.client.mlog.error("Error in get_offenses(): " + str(e))
            return None
        return offenses

    def get_rule(self, rule):
        fields = ["name", "type", "origin"]
        params = {
            "fields": ",".join(fields),
        }
        try:
            rule = self.client.request(
                method="GET",
                path="/api/analytics/rules/" + str(rule),
                params=params,
            )
        except requests.exceptions.RequestException as e:
            self.client.mlog.error("Error in get_rule(): " + str(e))

        return rule

    def set_tag(self, offense, TEST=False):
        if TEST:
            self.client.mlog.warning(
                "TEST: set_tag() - will not be executed. This means that the offenses will not be acknowledged!"
            )
            return
        try:
            if not TEST:
                _ = self.client.request(
                    method="POST",
                    path="/api/siem/offenses/" + str(offense),
                    params={
                        "fields": "",
                        "follow_up": "true",
                    },
                )
        except requests.exceptions.RequestException as e:
            self.client.mlog.error("Error in set_tag(): " + str(e))

    def create_note(self, offense, ticket):
        try:
            _ = self.client.request(
                method="POST",
                path="/api/siem/offenses/{:d}/notes".format(offense),
                params={
                    "fields": "",
                    "note_text": "Ticket #" + str(ticket),
                },
            )
        except requests.exceptions.RequestException as e:
            self.client.mlog.error("Error in create_note(): " + str(e))

    def search(self, aql: str):
        # POST /api/ariel/searches
        url = "{:s}/api/ariel/searches".format(self.client.host)
        self.client.mlog.debug("qradar.search(): POST /api/ariel/searches")
        response = self.client.request(
            method="POST",
            url=url,
            params={
                "query_expression": aql,
            },
            timeout=CONNECTION_TIMEOUT,
        )
        body = response.json()
        if response.status_code != 201:
            self.client.mlog.error("qradar.search(): Got response: " + body["message"])
            return Exception("qradar.search(): Got response: " + body["message"])

        # GET /api/ariel/searches/{search_id}
        self.client.mlog.debug("qradar.search(): GET /api/ariel/searches/" + body["search_id"] + ". Start polling.")
        url += "/" + body["search_id"]
        i = 0
        while body["status"] not in ["COMPLETED", "ERROR"]:
            if i > MAX_TRIES_QRADAR_SEARCH:
                self.client.mlog.error(
                    "qradar.search(): Canceled API request for search status check. Reason: Needed more than 6 Minutes for getting results."
                )
                return Exception(
                    "qradar.search(): Canceled API request for search status check. Reason: Needed more than 6 Minutes for getting results."
                )

            time.sleep(SEARCH_POLLING_INTERVAL)
            i += 1

            response = self.client.request(method="GET", url=url, timeout=CONNECTION_TIMEOUT)
            if response.status_code != 200:
                self.client.mlog.warning(body["message"])
                response.raise_for_status()
                continue
            body = response.json()
            self.client.mlog.debug("qradar.search(): Progress: {:3d}%".format(body["progress"]))

        if body["status"] == "ERROR":
            self.client.mlog.error("qradar.search() Failed search: " + body["error_messages"])
            return Exception("qradar.search() Failed search: " + body["error_messages"])

        # GET /api/ariel/searches/{search_id}/results
        url += "/results"
        self.client.mlog.debug("qradar.search(): GET /api/ariel/searches/{:s}/results".format(body["search_id"]))
        response = self.client.request(method="GET", url=url, timeout=CONNECTION_TIMEOUT)

        body = response.json(object_pairs_hook=collections.OrderedDict)
        if response.status_code != 200:
            self.client.mlog.error("qradar.search(): Got response: " + body["message"])
            return Exception("qradar.search(): Got response: " + body["message"])

        try:
            events = body["events"]
        except KeyError:
            self.client.mlog.error("qradar.search(): Failed to parse events from resposne.")
            return Exception("qradar.search(): Failed to parse events from resposne.")

        if events is None or len(events) == 0:
            self.client.mlog.debug("qradar.search(): Got no results.")
            return None

        if len(events) > MAX_RESULTS_QRADAR_SEARCH:
            self.client.mlog.warning("qradar.search(): Got more results than allowed. Truncating.")
            events = events[:MAX_RESULTS_QRADAR_SEARCH]

        return events

    def dns_lookup(self, ip: str, polling_frequency: float = 1.0):
        # POST /api/services/dns_lookups
        url = "{:s}/api/services/dns_lookups".format(self.client.host)
        self.client.mlog.debug("qradar.dns_lookup(): POST /api/services/dns_lookups")
        response = self.client.request(
            method="POST",
            url=url,
            params={
                "IP": ip,
            },
            timeout=CONNECTION_TIMEOUT,
        )
        body = response.json()
        if response.status_code != 201:
            self.client.mlog.error("qradar.dns_lookup(): Got response: " + body["message"])
            return Exception("qradar.dns_lookup(): Got response: " + body["message"])

        # GET /api/services/dns_lookups/{dns_lookup_id}
        url += "/{:d}".format(body["id"])
        while body["status"] not in ["COMPLETED", "ERROR"]:
            time.sleep(polling_frequency)
            self.client.mlog.debug("qradar.dns_lookup(): GET /api/services/dns_lookups/{:d}".format(body["id"]))
            response = self.client.request(
                method="GET",
                url=url,
                timeout=CONNECTION_TIMEOUT,
            )
            if response.status_code != 200:
                self.client.mlog.warning("qradar.dns_lookup(): " + body["message"])
                continue
            body = response.json()
            self.client.mlog.debug("qradar.dns_lookup(): Progress: {:3d}%".format(body["progress"]))

        if body["status"] == "ERROR":
            self.client.mlog.error("qradar.dns_lookup(): Failed search: " + error_message["message"])
            return Exception("qradar.dns_lookup(): Failed search: " + error_message["message"])

        message = json.loads(body["message"])
        return message[0]


def create_flow_from_events(mlog, offense_id, all_events):
    """Creates flows from a list of events.

    Args:
        mlog (logging.Logger): Logger to use.
        offense_id (int): Offense ID.
        all_events (list): List of events.

    Returns:
        Flow: Flow object.
    """

    mlog.debug("Creating flows from events...")
    flow_list = []

    for event in all_events:
        mlog.debug("Creating flow from event: " + str(event))

        try:
            if event["Source IP"] == None or event["Source IP"] == "NoneNone":
                continue
            if event["Destination IP"] == None or event["Destination IP"] == "NoneNone":
                continue
            if event["Source IP"] == event["Destination IP"]:
                continue

            file = None
            http = None
            dns = None
            device = None

            if dict_get(event, "HTTP - Method") != None:
                mlog.debug("Creating HTTP context for event: " + repr(event))
                http = HTTP(
                    offense_id,
                    event["HTTP - Method"],
                    "HTTPS" if event["HTTP - URL"].lower().startswith("https") else "HTTP",
                    event["HTTP - Hostname"],
                    event["HTTP - Status"],
                    path=event["HTTP - URL"],
                    user_agent=event["HTTP - User Agent"],
                    referer=event["HTTP - Referer"],
                    request_body=event["HTTP - Request Body"],
                    response_body=event["HTTP - Response Body"],
                    request_headers=event["HTTP - Request Headers"],
                    http_version=event["HTTP - Version"],
                    response_headers=event["HTTP - Response Headers"],
                    file=file,
                    timestamp=event["Log Source Time"],
                )
            elif dict_get(event, "Server Name Indication") != None:
                mlog.debug("Creating HTTPS context for event: " + repr(event))
                http = HTTP(offense_id, "Unknown (Encrypted)", "HTTPS", event["Server Name Indication"], None)

            if dict_get(event, "DNS - Query") != None:
                query_response_ip = cast_to_ipaddress(event["DNS - Query Response"], None)
                dns_type = "A"
                if type(query_response_ip) == ipaddress.IPv6Address:
                    dns_type = "AAAA"

                mlog.debug("Creating DNS context for event: " + repr(event))
                dns = DNSQuery(
                    offense_id,
                    type=dns_type,
                    query=event["DNS - Query"],
                    query_response=event["DNS - Query Response"],
                    timestamp=event["Log Source Time"],
                    has_response=event["DNS - Query Response"] != None,
                )

            protocol = "Undefined"
            if http != None:
                protocol = http.type
            elif event["Destination Port"] == 53 or event["Source Port"] == 53:
                protocol = "DNS"
            elif event["Destination Port"] == 80 or event["Source Port"] == 80:
                protocol = "HTTP"
            elif event["Destination Port"] == 443 or event["Source Port"] == 443:
                protocol = "HTTPS"
            elif event["Destination Port"] == 22 or event["Source Port"] == 22:
                protocol = "SSH"
            elif event["Destination Port"] == 23 or event["Source Port"] == 23:
                protocol = "Telnet"
            elif event["Destination Port"] == 25 or event["Source Port"] == 25:
                protocol = "SMTP"
            elif event["Destination Port"] == 110 or event["Source Port"] == 110:
                protocol = "POP3"
            elif event["Destination Port"] == 143 or event["Source Port"] == 143:
                protocol = "IMAP"
            elif event["Destination Port"] == 389 or event["Source Port"] == 389:
                protocol = "LDAP"
            elif event["Destination Port"] == 636 or event["Source Port"] == 636:
                protocol = "LDAPS"
            elif event["Destination Port"] == 1433 or event["Source Port"] == 1433:
                protocol = "MSSQL"
            elif event["Destination Port"] == 3306 or event["Source Port"] == 3306:
                protocol = "MySQL"
            elif event["Destination Port"] == 3389 or event["Source Port"] == 3389:
                protocol = "RDP"
            elif event["Destination Port"] == 5432 or event["Source Port"] == 5432:
                protocol = "PostgreSQL"
            elif event["Destination Port"] == 5985 or event["Source Port"] == 5985:
                protocol = "WinRM"

            firewall_action = "Permit"
            if any(word in event["Event Name"] for word in ["Blocked", "Denied", "Drop", "Deny"]):
                firewall_action = "Deny"
            elif "Reject" in event["Event Name"]:
                firewall_action = "Reject"

            rule_id = dict_get(event, "Firewall - Rule ID")
            rule_id = int(rule_id) if rule_id else None

            if event["Source Asset Name"] != None:
                src_ip = cast_to_ipaddress(event["Source IP"], False)
                src_ip_private = src_ip.is_private if src_ip != None else False

                device = ContextDevice(
                    event["Source Asset Name"],
                    src_ip if src_ip_private else None,
                    src_ip if not src_ip_private else None,
                    [src_ip] if src_ip != None else None,
                )

            if event["Destination Asset Name"] != None:
                dst_ip = cast_to_ipaddress(event["Destination IP"], False)
                dst_ip_private = dst_ip.is_private if dst_ip != None else False

                device = ContextDevice(
                    event["Destination Asset Name"],
                    dst_ip if dst_ip_private else None,
                    dst_ip if not dst_ip_private else None,
                    [dst_ip] if dst_ip != None else None,
                )

            mlog.debug("Creating flow context for event: " + repr(event))
            flow = ContextFlow(
                offense_id,
                event["Log Source Time"],
                "IBM QRadar",
                event["Source IP"],
                event["Source Port"],
                event["Destination IP"],
                event["Destination Port"],
                protocol=protocol,
                flow_source=event["Log Source"],
                device=device,
                source_hostname=event["Source Asset Name"],
                destination_hostname=event["Destination Asset Name"],
                category=event["Event Name"],
                sub_category=event["Low Level Category"],
                firewall_action=firewall_action,
                firewall_rule_id=rule_id,
                http=http,
                dns_query=dns,
            )

            mlog.debug("Flow context created: " + str(flow))
            flow_list.append(flow)

            # TODO: Add support for QRadar flows instead of just events

        except KeyError as e:
            mlog.warning("Missing key in event: " + str(event) + " - " + str(e) + ". Skipping event.")
            continue

    return flow_list


def create_logs_from_events(mlog, offense_id, all_events):
    """Creates ContextLog objects from a list of events.

    Args:
        mlog (logging.Logger): Logger to use.
        offense_id (int): Offense ID.
        all_events (list): List of events.

    Returns:
        list: Log objects.
    """

    mlog.debug("Creating logs from events...")
    log_list = []

    for event in all_events:
        mlog.debug("Creating log from event: " + str(event))

        try:
            device = None
            custom_fields = {}

            if event["Source Asset Name"] != None:
                src_ip = cast_to_ipaddress(event["Source IP"], False)
                src_ip_private = src_ip.is_private if src_ip != None else False

                device = ContextDevice(
                    event["Source Asset Name"],
                    src_ip if src_ip_private else None,
                    src_ip if not src_ip_private else None,
                    [src_ip] if src_ip != None else None,
                )

            elif event["Destination Asset Name"] != None:
                dst_ip = cast_to_ipaddress(event["Destination IP"], False)
                dst_ip_private = dst_ip.is_private if dst_ip != None else False

                device = ContextDevice(
                    event["Destination Asset Name"],
                    dst_ip if dst_ip_private else None,
                    dst_ip if not dst_ip_private else None,
                    [dst_ip] if dst_ip != None else None,
                )

            severity = dict_get(event, "Severity", "UNKNOWN")
            if severity == "UNKNOWN":
                severity = "INFO" if "INFO" in dict_get(event, "Event Name", "UNKNOWN").upper() else severity
                severity = "WARNING" if "WARNING" in dict_get(event, "Event Name", "UNKNOWN").upper() else severity
                severity = "ERROR" if "ERROR" in dict_get(event, "Event Name", "UNKNOWN").upper() else severity
                severity = "CRITICAL" if "CRITICAL" in dict_get(event, "Event Name", "UNKNOWN").upper() else severity
                severity = "DEBUG" if "DEBUG" in dict_get(event, "Event Name", "UNKNOWN").upper() else severity

            custom_fields = {
                k: event[k]
                for k in event
                if k
                not in [
                    "Log Source Time",
                    "Log Source",
                    "Source IP",
                    "Source Asset Name",
                    "Destination Asset Name",
                    "Event Name",
                    "Low Level Category",
                    "Destination IP",
                    "Destination Port",
                    "Source Port",
                ]
            }

            mlog.debug("Creating log context for event: " + repr(event))
            log = ContextLog(
                offense_id,
                event["Log Source Time"],
                event["Message"] if "Message" in event else None,
                event["Log Source"],
                event["Source IP"],
                log_source_device=device,
                log_type=event["Event Name"],
                log_severity=severity,
                log_custom_fields=custom_fields,
            )
            mlog.debug("Log context created: " + str(log))
            log_list.append(log)

        except KeyError as e:
            mlog.warning("Missing key in event: " + str(event) + " - " + str(e) + ". Skipping event.")
            continue

    return log_list


def create_files_from_events(mlog, offense_id, all_events):
    """Creates ContextFile objects from a list of events.

    Args:
        mlog (logging.Logger): Logger to use.
        offense_id (int): Offense ID.
        all_events (list): List of events.

    Returns:
        list: File objects.
    """

    mlog.debug("Creating files from events...")
    file_list = []

    for event in all_events:
        mlog.debug("Creating file from event: " + str(event))

        try:
            file = None

            if dict_get(event, "File Hash") != None:
                # Get filename from end of the filename path
                file_name = dict_get(event, "Filename")
                if file_name and "/" in file_name and len(file_name.split("/")) > 1:
                    file_name = file_name.split("/")[-1]

                file = ContextFile(
                    offense_id,
                    event["Log Source Time"],
                    "File Transfer",
                    file_name,
                    event["File Hash"],
                    file_path=event["Filename"],
                )
                mlog.debug("File context created: " + str(file))
                file_list.append(file)
        except KeyError as e:
            mlog.warning("Missing key in event: " + str(event) + " - " + str(e) + ". Skipping event.")
            continue

    return file_list


def zs_provide_new_detections(config, TEST=False) -> List[Detection]:
    """
    This function is used to provide new detections to Z-SOAR.
    :param config: The configuration of the integration.
    :param TEST: If set to "TEST", the function will not acknowledge the offenses.
    :return: A list of detections.
    """
    mlog = init_logging(config)
    mlog.info("zs_provide_new_detections() called.")
    detections = []
    socket.setdefaulttimeout = CONNECTION_TIMEOUT

    try:
        qradar_url = config["qradar_url"]
        qradar_api_key = config["qradar_api_key"]
        qradar_verify_certs = config["qradar_verify_certs"]
    except KeyError as e:
        mlog.critical("Missing config parameters: " + e)
        return detections

    requests.packages.urllib3.disable_warnings()

    qradar = QRadar(qradar_url, qradar_api_key, qradar_verify_certs, mlog)

    # QRadar Offenses
    mlog.debug("QRadar: Connecting to {:s} ...".format(qradar_url))
    offenses = qradar.get_offenses()
    offenses = offenses.json()
    if not offenses:
        mlog.info("QRadar: Done Quering QRadar SIEM (0 Hits)")
        return []
    mlog.info("Found {:d} new offenses".format(len(offenses)))

    for offense in offenses:
        try:
            # QRadar Rules
            rule_list = []
            rules = {}

            # Get rules associated with offenses
            for rule in offense["rules"]:
                rules[rule["id"]] = {}

            # Get rule details for each rule
            for rule_id in rules.keys():
                rules[rule_id] = qradar.get_rule(rule_id).json()
                rules[rule_id]["id"] = rule_id

            # Link to offense
            offense["url"] = "{:s}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={:d}".format(
                qradar_url,
                offense["id"],
            )

            # Create rule objects for each offense and rule
            rule_list = []
            for i in range(len(offense["rules"])):
                offense["rules"][i] = rules[offense["rules"][i]["id"]]
                rule_list.append(
                    Rule(
                        offense["rules"][i]["id"],
                        offense["rules"][i]["name"],
                        tags=[offense["rules"][i]["origin"], offense["rules"][i]["type"]],
                    )
                )
            offense["start_time"] = datetime.datetime.fromtimestamp(
                offense["start_time"] / 1000,
                tz=dateutil.tz.gettz("Europe/Berlin"),
            )

            mlog.info("Processing new offense with ID " + str(offense["id"]) + " ...")
            mlog.debug("Offense content: " + str(offense))
            host_ip = cast_to_ipaddress(offense["offense_source"], False)

            device = ContextDevice(None, host_ip)

            detection = Detection(
                "IBM QRadar",
                offense["description"],
                rule_list,
                offense["start_time"],
                "A new offense has been created.",
                host_ip=host_ip,
                severity=offense["severity"],
                device=device,
                uuid=offense["id"],
                url=offense["url"],
            )
            try:
                qradar.set_tag(offense["id"], TEST)  # acknowledge offense
                detections.append(detection)
            except Exception:
                mlog.error(
                    "[ANTI-LOOP] Failed to acknowledge offense with offense ID "
                    + str(offense["id"])
                    + ". Will not return detection in order to repeated detection alerts."
                )

        except Exception as e:
            mlog.error("Uncatched exception in zs_provide_new_detections(): " + (traceback.format_exc()))

    mlog.info("Done Quering QRadar SIEM (with Hit(s))")
    return detections


def zs_provide_context_for_detections(
    detection_report: DetectionReport, required_type: type, TEST="", search_type=None, search_value=None
) -> list:
    """
    This function is used to provide context to Z-SOAR.
    :param config: The configuration of the integration.
    :param TEST: If set to "TEST", the function will return a test context.
    :return: A list of contexts, an empty list if no context is available or an exception if an error occurred.
    """
    config = Config().cfg
    config = config["integrations"]["ibm_qradar"]
    mlog = init_logging(config)
    mlog.info(
        "zs_provide_context() called with required type "
        + str(required_type)
        + " and search_type '"
        + str(search_type)
        + "' and search_value '"
        + str(search_value)
        + "'."
    )
    contexts = []
    socket.setdefaulttimeout = CONNECTION_TIMEOUT
    search_type = search_type.lower()

    if required_type not in [ContextFlow, ContextLog, ContextFile, any]:
        mlog.error("Invalid required_type: " + str(required_type))
        raise ValueError("Invalid required_type: " + str(required_type))

    if search_type not in ["offense"]:
        mlog.error("Invalid search_type: " + str(search_type))
        raise ValueError("Invalid search_type: " + str(search_type))

    if not search_value:
        mlog.error("No search_value provided.")
        raise ValueError("No search_value provided.")
    try:
        qradar_url = config["qradar_url"]
        qradar_api_key = config["qradar_api_key"]
        qradar_verify_certs = config["qradar_verify_certs"]
    except KeyError as e:
        mlog.critical("Missing config parameters: " + e)
        return contexts

    requests.packages.urllib3.disable_warnings()
    qradar = QRadar(qradar_url, qradar_api_key, qradar_verify_certs, mlog)

    ### OFFENSES ###
    if search_type == "offense":
        if type(search_value) != int:
            try:
                search_value = int(search_value)
            except Exception:
                mlog.error("Invalid search_value: " + str(search_value))
                raise ValueError("Invalid search_value: " + str(search_value))

        session = requests.Session()
        session.headers["Accept"] = "application/json"
        session.headers["Version"] = "10"
        session.headers["SEC"] = qradar_api_key
        session.verify = False

        mlog.info("Getting further offense context for offense ID " + str(search_value))

        # GET /api/siem/offenses/{offense_id}
        fields = [
            "description",
            "last_updated_time",
            "start_time",
            "rules",
        ]
        params = {
            "fields": ",".join(fields),
        }
        try:
            response = session.get(
                "{:s}/api/siem/offenses/{:d}".format(
                    qradar_url,
                    search_value,
                ),
                timeout=CONNECTION_TIMEOUT,
                params=params,
            )

            if type(response) == Exception:
                return response

            if response.status_code != 200:
                mlog.error(f"Got response code {str(response.status_code)} in zs_provide_context(): " + response.text)
                return Exception("Got response code " + str(response.status_code) + " in zs_provide_context()")

        except Exception as e:
            mlog.error("Error establishing connection to QRadar in zs_provide_context(): " + str(e))
            return Exception("Error establishing connection to QRadar in zs_provide_context(): " + str(e))

        body = response.json()

        mlog.info("Updating detection's description: " + repr(body["description"]))
        detection: Detection = detection_report.detections[0]
        detection.rules[0].description = body["description"]

        ## CONTEXT FLOW ##
        if required_type == ContextFlow or required_type == any:
            start = body["start_time"]
            stop = body["last_updated_time"]

            mlog.info(
                f"Querying QRadar SIEM for offense ID {search_value} and flow log sources to get further context for the offense..."
            )

            all_events = []
            for log_source in FLOW_LOG_SOURCES:
                if not log_source in QUERIES[qradar_url]:
                    mlog.warning("No query for flow conteext log source " + str(log_source) + " defined. Using fallback.")
                    log_source = "FALLBACK"

                aql = format_aql(QUERIES[qradar_url][log_source], search_value, start, stop)
                events = qradar.search(aql)

                if type(events) == Exception:
                    return events

                if events is None:
                    mlog.warning("Got no results for log source " + str(log_source) + ".")
                    continue

                mlog.debug("Got {:d} results for log source {:s}.".format(len(events), log_source))
                all_events += events

            if not all_events or len(all_events) == 0:
                mlog.warning("Got no results for offense ID " + str(search_value) + ".")
                return []

            mlog.info("Collected {:d} events for offense ID {:d}.".format(len(all_events), search_value))

            flows = create_flow_from_events(mlog, search_value, all_events)
            if flows and len(flows) > 0:
                mlog.info("Created {:d} flow(s) related to offense ID {:d}.".format(len(flows), search_value))
            else:
                mlog.warning("No flow created for offense ID " + str(search_value) + ".")
            contexts += flows

        ## CONTEXT LOG ##
        if required_type == ContextLog or required_type == any:
            start = body["start_time"]
            stop = body["last_updated_time"]

            mlog.info(
                f"Querying QRadar SIEM for offense ID {search_value} and log log sources to get further context for the offense..."
            )

            all_events = []
            for log_source in LOG_LOG_SOURCES:
                if not log_source in QUERIES[qradar_url]:
                    mlog.warning("No query for log context log source " + str(log_source) + " defined. Using fallback.")
                    log_source = "FALLBACK"

                aql = format_aql(QUERIES[qradar_url][log_source], search_value, start, stop)
                events = qradar.search(aql)

                if type(events) == Exception:
                    return events

                if events is None:
                    mlog.warning("Got no results for log source " + str(log_source) + ".")
                    continue

                mlog.debug("Got {:d} results for log source {:s}.".format(len(events), log_source))
                all_events += events

            if not all_events or len(all_events) == 0:
                mlog.warning("Got no results for offense ID " + str(search_value) + ".")
                return []

            mlog.info("Collected {:d} events for offense ID {:d}.".format(len(all_events), search_value))

            logs = create_logs_from_events(mlog, search_value, all_events)
            if logs and len(logs) > 0:
                mlog.info("Created {:d} log(s) related to offense ID {:d}.".format(len(logs), search_value))
            else:
                mlog.warning("No log created for offense ID " + str(search_value) + ".")
            contexts += logs

        ## CONTEXT FILE ##
        if required_type == ContextFile or required_type == any:
            start = body["start_time"]
            stop = body["last_updated_time"]

            mlog.info(
                f"Querying QRadar SIEM for offense ID {search_value} and file log sources to get further context for the offense..."
            )

            all_events = []
            for log_source in FILE_LOG_SOURCES:
                if not log_source in QUERIES[qradar_url]:
                    mlog.warning("No query for file context log source " + str(log_source) + " defined. Using fallback.")
                    log_source = "FALLBACK"

                aql = format_aql(QUERIES[qradar_url][log_source], search_value, start, stop)
                events = qradar.search(aql)

                if type(events) == Exception:
                    return events

                if events is None:
                    mlog.warning("Got no results for log source " + str(log_source) + ".")
                    continue

                mlog.debug("Got {:d} results for log source {:s}.".format(len(events), log_source))
                all_events += events

            if not all_events or len(all_events) == 0:
                mlog.warning("Got no results for offense ID " + str(search_value) + ".")
                return []

            mlog.info("Collected {:d} events for offense ID {:d}.".format(len(all_events), search_value))

            files = create_files_from_events(mlog, search_value, all_events)
            if files and len(files) > 0:
                mlog.info("Created {:d} file(s) related to offense ID {:d}.".format(len(files), search_value))
            else:
                mlog.warning("No file created for offense ID " + str(search_value) + ".")
            contexts += files

        session.close()
        mlog.info("Returning {:d} context(s) for offense ID {:d}.".format(len(contexts), search_value))
        return contexts
