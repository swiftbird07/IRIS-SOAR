# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with IBM QRadar.
#
# This module is capable of:
# [ ] Providing new detections.
# [ ] Providing context for detections of type [ContextFlow | ContextLog]
# [ ] User interactive setup.
#
# Integration Version: 0.0.1
# Currently limited to process related detections and contexts.

import logging
from typing import Union, List
import datetime
import requests
from ssl import create_default_context
import sys
import json
import abc
import json
import logging
import time

import datetime
import json
import traceback
import dateutil.tz
import requests
import os



import lib.logging_helper as logging_helper

# For new detections:
from lib.class_helper import Rule, Detection, ContextProcess, ContextFlow, ContextDevice

# For context for detections:
from lib.class_helper import DetectionReport, ContextFlow, ContextLog, ContextProcess, cast_to_ipaddress, Location, DNSQuery, ContextFile, Certificate, ContextRegistry
from lib.generic_helper import dict_get, get_from_cache, add_to_cache, default

if __name__ == "__main__":
    sys.exit() # TODO: Add interactive setup

QUERIES = {
    "qradar.cloud.swiftbird.de": {
        # UC #011 - Default admin account usage attempt detected
        0: {
            "SELECT": (
                "DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS 'Log Source Time'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "destinationip AS 'Destination IP'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "username AS 'Username'",
                "\"Alert - Created\"",
                "\"Alert - Action\"",
                "\"Alert - Category\"",
                "\"Alert - Domain\"",
                "\"Alert - SID\"",
                "\"Alert - Severity\"",
                "\"Alert - Signature\"",
                "\"Alert - Updated\"",
                "\"Application\"",
                "\"Certificate - Issuer\"",
                "\"Certificate - Subject\"",
                "\"DNS - Query\"",
                "\"DNS - Query Response\"",
                "\"DNS - Type\"",
                "\"Destination Host Name\"",
                "\"File Hash\"",
                "\"Filename\"",
                "\"HTTP - Content Type\"",
                "\"HTTP - Hostname\"",
                "\"HTTP - Method\"",
                "\"HTTP - Protocol\"",
                "\"HTTP - Status\"",
                "\"HTTP - URL\"",
                "\"HTTP - User Agent\"",
                "\"Server Name Indication\"",
            ),
            "FROM": "events",
            "WHERE": (
                "LOGSOURCETYPENAME(devicetype) <> 'Custom Rule Engine'",
            ),
            "ORDER BY": (
                "devicetime ASC",
            ),
        },
        # UC #021 - Network connection to designated country
        100758: {
            "SELECT": (
                "DATEFORMAT(MIN(devicetime), 'yyyy-MM-dd HH:mm:ss') AS 'Start'",
                "DATEFORMAT(MAX(devicetime), 'yyyy-MM-dd HH:mm:ss') AS 'Stop'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "IF UNIQUECOUNT(sourceport) = 1 THEN STR(sourceport) ELSE '*' AS 'Source Port'",
                "destinationip AS 'Destination IP'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "IF UNIQUECOUNT(destinationport) = 1 THEN STR(destinationport) ELSE '*' AS 'Destination Port'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "SUM(eventcount) AS 'Count'",
            ),
            "FROM": "events",
            "WHERE": (
                "LOGSOURCETYPENAME(devicetype) <> 'Custom Rule Engine'",
            ),
            "GROUP BY": (
                "logsourceid",
                "sourceip",
                "destinationip",
                "qid",
            ),
            "ORDER BY": (
                "\"Start\" ASC",
            ),
        },
        # UC #036 - Authentication attempt outside office working hours
        100756: {
            "SELECT": (
                "DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm:ss') AS 'Log Source Time'",
                "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                "sourceip AS 'Source IP'",
                "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                "destinationip AS 'Destination IP'",
                "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                "CATEGORYNAME(category) AS 'Low Level Category'",
                "QIDNAME(qid) as 'Event Name'",
                "username AS 'Username'",
                "\"EventID\" AS 'Event ID'",
                "\"Logon Type\"",
            ),
            "FROM": "events",
            "WHERE": (
                "LOGSOURCETYPENAME(devicetype) <> 'Custom Rule Engine'",
            ),
            "ORDER BY": (
                "devicetime ASC",
            ),
        },
#         # #0022_Login failures followed by success
         100853: {
             "SELECT": ( 
                 "DATEFORMAT(MIN(devicetime), 'yyyy-MM-dd HH:mm:ss') AS 'Start', DATEFORMAT(MAX(devicetime), 'yyyy-MM-dd HH:mm:ss') AS 'Stop'", 
                 "LOGSOURCENAME(logsourceid) AS 'Log Source'",
                 "sourceip AS 'Source IP'",
                 "ASSETHOSTNAME(sourceip) AS 'Source Asset Name'",
                 "destinationip AS 'Destination IP'",
                 "ASSETHOSTNAME(destinationip) AS 'Destination Asset Name'",
                 "QIDNAME(qid) as 'Event Name'",
                 "CATEGORYNAME(category) AS 'Low Level Category'",
                 "username AS 'Username'",
                 "SUM(eventcount) AS 'Count'",
             ),
             "FROM": "events",
             "WHERE": (
                 "LOGSOURCETYPENAME(devicetype) <> 'Custom Rule Engine'",
             ),
             "GROUP BY": ( 
                 "logsourceid, sourceip, destinationip, qid, username",
             ),
             "ORDER BY": (
                  "'Start' ASC",
             ),
         },
    }
}



logger = logging.getLogger(__name__)


# Classses useful for QRadar:
class Client(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, host, verify: bool = False):
        self.host = host

        if not verify:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        self.session.headers["Version"] = "12"
        self.session.verify = verify

    def request(self, method: str, path: str, params: dict = None):
        assert method in ("GET", "POST", "DELETE")
        logger.info("{:s} {:s}".format(method, path))
        response = self.session.request(
            method = method,
            url = self.host + path,
            params = params,
            timeout = 10.0,
        )
        response.raise_for_status()
        body = response.json()
        return body

    def search(self, aql: str, polling_frequency: float = 1.0):
        # POST /api/ariel/searches
        url = "https://{:s}/api/ariel/searches".format(self.host)
        logger.info("POST /api/ariel/searches")
        response = self.session.post(
            url = url,
            params = {
                "query_expression": aql,
            },
            timeout = 10.0,
        )
        body = response.json()
        if response.status_code != 201:
            logger.critical(body["message"])
            return None

        # GET /api/ariel/searches/{search_id}
        url += "/" + body["search_id"]
        while body["status"] not in ["COMPLETED", "ERROR"]:
            time.sleep(polling_frequency)
            logger.info("GET /api/ariel/searches/" + body["search_id"])
            response = self.session.get(
                url = url,
                timeout = 10.0,
            )
            if response.status_code != 200:
                logger.warning(body["message"])
                continue
            body = response.json()
            logger.debug("{:s} ({:3d} %)".format(
                body["search_id"],
                body["progress"],
            ))
        if body["status"] == "ERROR":
            for error_message in body["error_messages"]:
                logger.critical(error_message["message"])
            return None

        # GET /api/ariel/searches/{search_id}/results
        url += "/results"
        logger.info("GET /api/ariel/searches/{:s}/results".format(body["search_id"]))
        response = self.session.get(
            url = url,
            timeout = 10.0,
        )
        body = response.json()
        if response.status_code != 200:
            logger.critical(body["message"])
            return None
        return body

    def dns_lookup(self, ip: str, polling_frequency: float = 1.0):
        # POST /api/services/dns_lookups
        url = "https://{:s}/api/services/dns_lookups".format(self.host)
        logger.info("POST /api/services/dns_lookups")
        response = self.session.post(
            url = url,
            params = {
                "IP": ip,
            },
            timeout = 10.0,
        )
        body = response.json()
        if response.status_code != 201:
            logger.critical(body["message"])
            return None

        # GET /api/services/dns_lookups/{dns_lookup_id}
        url += "/{:d}".format(body["id"])
        while body["status"] not in ["COMPLETED", "ERROR"]:
            time.sleep(polling_frequency)
            logger.info("GET /api/services/dns_lookups/{:d}".format(body["id"]))
            response = self.session.get(
                url = url,
                timeout = 10.0,
            )
            if response.status_code != 200:
                logger.warning(body["message"])
                continue
            body = response.json()
            logger.debug("{:d} {:s}".format(
                body["id"],
                body["status"],
            ))
        if body["status"] == "ERROR":
            for error_message in body["error_messages"]:
                logger.critical(error_message["message"])
            return None
        message = json.loads(body["message"])
        return message[0]

    def __del__(self):
        self.session.close()

class CredentialClient(Client):

    def __init__(self, host, username, password, verify: bool = False):
        super().__init__(host, verify)
        self.session.auth = (username, password)

class TokenClient(Client):

    def __init__(self, host, token, verify: bool = False):
        super().__init__(host, verify)
        self.session.headers["SEC"] = token

# Other useful functions:
def format_aql(query, offense, start, stop):
    aql = ""
    # SELECT
    aql += "SELECT {:s}\n".format(
        ", ".join(query["SELECT"]) if "SELECT" in query else "*"
    )
    # FROM
    aql += "FROM {:s}\n".format(query["FROM"] if "FROM" in query else "events")
    # WHERE
    where = ["INOFFENSE({:d})".format(offense)]
    if "WHERE" in query:
        where += query["WHERE"]
    aql += "WHERE {:s}\n".format(" AND ".join(where))
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


def run_search(aql, session, tID):
    # POST /ariel/searches
    # session = requests.Session()

    params = {
        "query_expression": aql,
    }
    response = session.post(
        "https://{:s}/api/ariel/searches".format(
            URL,
        ),
        params=params,
    )
    if response.status_code != 201:
        mlog.info(
            "w",
            tID,
            "QRadar: Non-200 Status Code in API request for search initializing in runSearch() via analyse():",
            response.text,
        )
    body = response.json()
    mlog.debug("Search ID:   '{:s}'".format(body["search_id"]))

    # GET /ariel/searches/{search_id}
    i = 0

    while body["status"] not in ["COMPLETED", "ERROR"]:
        time.sleep(1)
        i += 1
        response = session.get(
            "https://{:s}/api/ariel/searches/{:s}".format(
                URL,
                body["search_id"],
            )
        )
        if response.status_code != 200:
            mlog.info(
                "w",
                tID,
                "QRadar: Non-200 Status Code in API request for search status check in runSearch() via analyse():",
                response.text,
            )
            return -1
        body = response.json()
        mlog.debug("Progress:    {:3d}%".format(body["progress"]))
    if body["status"] == "ERROR":
        mlog.info(
            "e",
            tID,
            "QRadar: ERROR in API request for search status check in runSearch() via analyse():",
            response.text,
        )
        return -1

    if i > 360:
        mlog.info(
            "w",
            tID,
            "QRadar: Canceled API request for search status check. Reason: Needed more than 6 Minutes for getting results in runSearch() via analyse():",
            response.text,
        )
        return -1

    # GET /ariel/searches/{search_id}/results
    response = session.get(
        "https://{:s}/api/ariel/searches/{:s}/results".format(
            URL,
            body["search_id"],
        )
    )
    if response.status_code != 200:
        mlog.info(
            "w",
            tID,
            "QRadar: Non-200 Status Code in API request for search fetching in runSearch() via analyse():",
            response.text,
        )
        return -1
    body = response.json(object_pairs_hook=collections.OrderedDict)

    if not body["events"]:
        mlog.info(
            "w",
            tID,
            "QRadar: Empty result in runSearch() via analyse():",
            response.text,
        )
        return -1
    return body["events"]


def format_results(events, format):
    if format in ("html", "markdown"):
        data = pd.DataFrame(data=events)
        if format == "html":
            tmp = data.to_html(index=False, classes=None)
            return tmp.replace(' class="dataframe"', "")
        elif format == "markdown":
            return data.to_markdown(index="false")
    elif format == "json":
        return json.dumps(events, ensure_ascii=False, sort_keys=False)


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


def get_indicators(data, tID):
    mlog.debug("QRadar: (Analyse Event Data) Fetching indicators for event data...")
    indicators = ""

    for i in data:
        indicators = check(i["Source IP"], indicators)
        indicators = check(i["Destination IP"], indicators)
        indicators = check(i["DNS - Query"], indicators)
        indicators = check(i["DNS - Query Response"], indicators)
        indicators = check(i["HTTP - User Agent"], indicators)
        indicators = check(str(i["HTTP - Hostname"]) + str(i["HTTP - URL"]), indicators)
        indicators = check(i["Certificate - Issuer"], indicators)
        indicators = check(i["Certificate - Subject"], indicators)
        indicators = check(i["Server Name Indication"], indicators)
        indicators = check(i["Filename"], indicators)
        indicators = check(i["File Hash"], indicators)

    print(indicators)
    return indicators





def init_logging(config):
    """Initializes the logging for this module.

    Args:
        config (dict): The configuration dictionary for this integration

    Returns:
        logging_helper.Log: The logging object
    """
    log_level_file = config["logging"]["log_level_file"]  # be aware that only configs from this integration are available not the general config
    log_level_stdout = config["logging"]["log_level_stdout"]
    log_level_syslog = config["logging"]["log_level_syslog"]

    mlog = logging_helper.Log(__name__, log_level_stdout=log_level_stdout, log_level_file=log_level_file)
    return mlog


class QRadar:
    def __init__(self, config_url, config_api_key, verify):
        self.client = TokenClient(
            config_url,
            config_api_key,
            verify
        )

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
            symlog.info.symlog.info(str(e))
            symlog.info.symlog.info(e.response.text)
            exit()
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
            symlog.info.symlog.info(str(e))
            symlog.info.symlog.info(e.response.text)
        return rule

    def set_tag(self, offense):
        try:
            if os.environ["OTRS_ORCH_PROD"] == "True":
                _ = self.client.request(
                    method="POST",
                    path="/api/siem/offenses/" + str(offense),
                    params={
                        "fields": "",
                        "follow_up": "true",
                    },
                )
        except requests.exceptions.RequestException as e:
            symlog.info.symlog.info(str(e))
            symlog.info.symlog.info(e.response.text)

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
            symlog.info.symlog.info(str(e))
            symlog.info.symlog.info(e.response.text)


    def add_events(self, ticketID, offense, config, tID):
        try:
            mlog.info("i", tID, "QRadar: Parsing Event Data for offenseID.")

            CLIENT_DOMAIN = "http://10.20.1.9"
            CLIENT_URL = (
                CLIENT_DOMAIN
                + "/otrs/nph-genericinterface.pl/Webservice/ALERTELAST_API"
            )

            client = Client(
                CLIENT_URL,
                "Agent_QRadar_SIEM",
                "AFadcCd9da5dcAbcfadca5aaEd3eaCE433CECA2ddEfAbdeaedcb45fdC4aed2ff",
            )
            client.session_create()

            articleSubject = "[QRadar] Events for Offense " + str(offense["id"])

            html, indicators = analyse(offense["id"], 0, "html", tID)

            try:
                html = str(html)
                html = html.replace("\n", "")
                articleBody = html + "<br><br>Indicators:<br>" + str(indicators)

                article = Article(
                    {
                        "Subject": articleSubject,
                        "Body": articleBody,
                        "MimeType": "text/html",
                        "Charset": "utf-8",
                    }
                )

                if os.environ["OTRS_ORCH_PROD"] == "True":
                    result = client.ticket_update(ticketID, article)
                    mlog.debug("QRadar: (Analyse Event Data) Result: ", result)
                else:
                    mlog.debug(
                        "QRadar: (Analyse Event Data) Would sent ticket now, but debug mode is activated. Here is the ticket body that would have been sent:\n\n",
                        articleBody,
                    )
            except:
                pass  # Likely Error from in analyse()

        except Exception as e:
            mlog.info(
                "e",
                tID,
                "QRadar: Uncatched exception in add_events() via alertqradar(): ",
                (traceback.format_exc()),
            )


def zs_provide_new_detections(config, TEST="") -> List[Detection]:
    """
    This function is used to provide new detections to Z-SOAR.
    :param config: The configuration of the integration.
    :param TEST: If set to "TEST", the function will return a test detection.
    :return: A list of detections.
    """
    mlog = init_logging(config)
    mlog.info("zs_provide_new_detections() called.")
    detections = []

    try:
        qradar_url = config["qradar_url"]
        qradar_api_key = config["qradar_api_key"]
        qradar_verify_certs = config["qradar_verify_certs"]
    except KeyError as e:
        mlog.critical("Missing config parameters: " + e)
        return detections

    requests.packages.urllib3.disable_warnings()


    qradar = QRadar(qradar_url, qradar_api_key, qradar_verify_certs)

    # QRadar Offenses
    mlog.debug("QRadar: Connecting to {:s} ...".format(qradar_url))
    offenses = qradar.get_offenses()
    mlog.info("Found {:d} new offenses".format(len(offenses)))
    if not offenses:
        mlog.info("QRadar: Done Quering QRadar SIEM (0 Hits)")
        return []

    # QRadar Rules
    rules = {}
    for offense in offenses:
        for rule in offense["rules"]:
            rules[rule["id"]] = {}
    for rule_id in rules.keys():
        rules[rule_id] = qradar.get_rule(rule_id)
    for offense in offenses:
        for i in range(len(offense["rules"])):
            offense["rules"][i] = rules[offense["rules"][i]["id"]]
        offense["start_time"] = datetime.datetime.fromtimestamp(
            offense["start_time"] / 1000,
            tz=dateutil.tz.gettz("Europe/Berlin"),
        )

    # Link to offense
    for offense in offenses:
        offense["url"] = "https://{:s}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={:d}".format(qradar_url, offense["id"],
        )

    for offense in offenses:
        try:
            mlog.debug(offense)
            host_ip = offense["offense_source"]
            device = ContextDevice(None, host_ip)

            detection = Detection(
                "IBM QRadar",
                offense["description"],
                offense["rules"],
                offense["start_time"],
                "A new offense has been created.",
                host_ip=host_ip,
                severity=offense["severity"],
                device=device,
                uuid=offense["id"],
                url=offense["url"],
            )
            try:
                qradar.set_tag(offense["id"]) # acknowledge offense
                detections.append(detection)  
            except Exception:
                mlog.error("[ANTI-LOOP] Failed to acknowledge offense with offense ID "+ str(offense["id"]) + ". Will not return detection in order to repeated detection alerts.")  
                        
        except Exception as e:
            mlog.error("Uncatched exception in zs_provide_new_detections(): " + (traceback.format_exc()))

    mlog.info("Done Quering QRadar SIEM (with Hit(s))")
    return detections


def zs_provide_context(config, TEST="") -> Union[ContextFlow, ContextLog]:
    """
    This function is used to provide context to Z-SOAR.
    :param config: The configuration of the integration.
    :param TEST: If set to "TEST", the function will return a test context.
    :return: A list of contexts.
    """
    mlog = init_logging(config)
    mlog.info("zs_provide_context() called.")
    contexts = []

    try:
        qradar_url = config["qradar_url"]
        qradar_api_key = config["qradar_api_key"]
        qradar_verify_certs = config["qradar_verify_certs"]
    except KeyError as e:
        mlog.critical("Missing config parameters: " + e)
        return contexts

    requests.packages.urllib3.disable_warnings()
    
    mlog.info("QRadar: Analyzing Event Data for offenseID ", offenseID)
    # requests
    session = requests.Session()
    # username = "ALERTQRADAR"
    # password = TOKEN
    # session.auth = (username, password)

    session.headers["Accept"] = "application/json"
    session.headers["Version"] = "10"
    session.headers["SEC"] = TOKEN
    session.verify = False

    if offenseID:
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
        response = session.get(
            "https://{:s}/api/siem/offenses/{:d}".format(
                URL,
                offenseID,
            ),
            params=params,
        )
        if response.status_code == 404:
            mlog.info(
                "w",
                tID,
                "QRadar: 404 Status Code in API request for offense lookup in analyse():",
                response.text,
            )
            return -1
        if response.status_code != 200:
            mlog.info(
                "w",
                tID,
                "QRadar: Non-200 (and non 404) Status Code in API request for offense lookup in analyse():",
                response.text,
            )
            return -1

        body = response.json()
        mlog.debug("Description: " + repr(body["description"]))
        rules = [r["id"] for r in body["rules"]]
        if not set(rules):
            mlog.debug("No queries defined for this offense!")

        start = body["start_time"]
        stop = body["last_updated_time"]

        for rule in rules:
            if not rule in QUERIES[URL]:
                rule = 0
            aql = format_aql(QUERIES[URL][rule], offenseID, start, stop)
            print(aql)
            events = run_search(aql, session, tID)

            try:
                if events < 0:
                    return -1
            except:
                pass
            results = format_results(events, format)
            indicators = get_indicators(events, tID)

    session.close()