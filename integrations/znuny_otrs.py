# Integration for Z-SOAR
# Created by: Martin Offermann
#
# This module is used to integrate Z-SOAR with Znuny (formally known as 'OTRS', but from here only called 'Znuny') Webservices.
# It enables Z-SOAR playbooks to use the Znuny Ticketsystem to create tickets and/or add notes to them.
#
# Although this module is a core component of Z-SOAR (cause for the 'Z' in the first place), it is internally handled as an integration,
# because in the future it may be possible to use other ticket systems as well.
# As this is also a 'normal' integration, it can be used to get new detections from Znuny into Z-SOAR and not only the other way around.
# It is also posssible to get context from Znuny into Z-SOAR (e.g. ticket information or using the ITSM CMDB).
#
# Integration Version: 0.0.1 
#
# This module is (currently) capable of:
# [X] Ticketing: Ticket creation
# [X] Ticketing: Adding notes to tickets
# [ ] Providing new detections.
# [ ] Providing context for detections of type [ContextDevice]
# [X] User interactive setup
#



# This module is heavily using the 'pyOTRS' library. Thanks to @frennkie
import pyotrs

import sys
from typing import Union, List
from lib.config_helper import Config
from lib.logging_helper import Log
import pandas as pd
import json

# For new detections:
from lib.class_helper import Rule, Detection, ContextProcess, ContextFlow

# For context for detections (remove unused types):
from lib.class_helper import DetectionReport, ContextFlow, ContextLog, ContextProcess, cast_to_ipaddress
from lib.generic_helper import dict_get, get_from_cache, add_to_cache

PRE_TAG = "[ZSOAR]" # Tag before the title of the ticket (without spaces)

TICKET_CONNECTOR_CONFIG_DEFAULT = {
    'Name': 'GenericTicketConnectorREST',
    'Config': {
        'SessionCreate': {'RequestMethod': 'POST',
                          'Route': '/Session',
                          'Result': 'SessionID'},
        'AccessTokenCreate': {'RequestMethod': 'POST',
                              'Route': '/Session',
                              'Result': 'AccessToken'},
        'SessionGet': {'RequestMethod': 'GET',
                       'Route': '/Session/:SessionID',
                       'Result': 'SessionData'},
        'TicketCreate': {'RequestMethod': 'POST',
                         'Route': '/Ticket',
                         'Result': 'TicketID'},
        'TicketGet': {'RequestMethod': 'GET',
                      'Route': '/Ticket/:TicketID',
                      'Result': 'Ticket'},
        'TicketGetList': {'RequestMethod': 'GET',
                          'Route': '/TicketList',
                          'Result': 'Ticket'},
        'TicketSearch': {'RequestMethod': 'GET',
                         'Route': '/Ticket',
                         'Result': 'TicketID'},
        'TicketUpdate': {'RequestMethod': 'PATCH',
                         'Route': '/Ticket/:TicketID',
                         'Result': 'TicketID'},
    }
}

config = Config().cfg
log_level_file = config["integrations"]["znuny_otrs"]["logging"]["log_level_file"]
log_level_stdout = config["integrations"]["znuny_otrs"]["logging"]["log_level_stdout"]
mlog = Log("integrations.znuny_otrs", log_level_file, log_level_stdout)

def main():
    # Check if argumemnt 'setup' was passed to the script
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        zs_integration_setup()
    elif len(sys.argv) > 1:
        print("Unknown argument: " + sys.argv[1])
        print("Usage: python3 " + sys.argv[0] + " --setup")
        sys.exit(1)


def zs_integration_setup(zsoar_main_call=False):
    # Import here because this is only needed for setup
    from lib.config_helper import setup_integration as set_int
    from lib.config_helper import setup_ask
    import tests.integrations.test_znuny_otrs as test_znuny_otrs

    intgr = "znuny_otrs"

    if not zsoar_main_call:
        print("This script will setup the integration 'Znuny/OTRS' (from here called just 'Znuny') for Z-SOAR.")
        print("Please enter the required information below.")
        print("")

    set_int(intgr, "url", "url", "Enter the URL to connect to to Znuny", additional_info="Example: https://tickets.example.com")

    set_int(intgr, "webservice_name", "str", "Enter the WebService name to use. E.g. GenericTicketConnectorREST")
    set_int(
        intgr,
        "username",
        "str",
        "Enter the Znuny username",
        additional_info="Be aware that this user needs access to create tickets to the selected queues.",
    )

    set_int(intgr, "password", "secret", "Enter the Znuny password for the user")

    set_int(
        intgr,
        "verify_certs",
        "y/n",
        "Verify Znuny certificates?",
        additional_info="If set to 'n', the connection will be insecure, but you can use self-signed certificates.",
    )

    set_int(intgr, "logging", "log_level", "Enter the log level to stdout", sub_config="log_level_stdout")

    set_int(intgr, "logging", "log_level", "Enter the log level to file", sub_config="log_level_file")

    set_int(intgr, "logging", "log_level", "Enter the log level to syslog", sub_config="log_level_syslog")

    set_int(intgr, "ticketing", "y/n", "Enable creating/adding to tickets in Znuny?", sub_config="enabled")

    set_int(
        intgr,
        "ticketing",
        "str",
        "Enter the name of the target queue to create tickets in",
        sub_config="target_queue",
        additional_info="Be aware that the user needs access to create tickets in this queue.",
    )

    set_int(intgr, "detection_provider", "y/n", "Enable providing new detections FROM Znuny?", sub_config="enabled")

    set_int(
        intgr,
        "detection_provider",
        "str",
        "Enter the name of the source queue to get new detections from",
        sub_config="source_queue",
        additional_info="Be aware that the user needs access to read tickets in this queue.",
    )

    set_int(intgr, "context_provider", "y/n", "Enable providing context from Znuny?", sub_config="enabled")

    set_int(
        intgr,
        "context_provider",
        "str",
        "Enter the name of the source queue to get context from",
        sub_config="itsm_customer",
        additional_info="Be aware that the user needs access to read tickets of this customer.",
    )

    print("")
    print("")
    print("Do you want to test the integration before enabling it?")
    test_now = setup_ask("y", available_responses_list=["y", "n"])
    if test_now == "y":
        print("Testing the integration...")
        result = test_znuny_otrs.test_zs_provide_new_detections()
        if result:
            print("Test successful!")
        else:
            print("Test failed!")
            print("Please check the log file for more information.")
            print("Please fix the issue and try again.")
            print("NOTICE: Not enabling the integration because the test failed.")
            sys.exit(1)

    set_int(intgr, "enabled", "y/n", message="Enable the integration now?")

    print("")
    print("Setup finished.")
    print("You can now use the integration in Z-SOAR!")

def zs_provide_new_detections(config, TEST="") -> List[Detection]:
    return NotImplementedError # TODO: Implement

def zs_provide_context_for_detections(
    config, detection_report: DetectionReport, required_type: type, TEST=False, UUID=None, UUID_is_parent=False,  maxContext=50
) -> Union[ContextFlow, ContextLog, ContextProcess]:
    return NotImplementedError # TODO: Implement

def ticket_check_merge(mlog, config, client: pyotrs.Client, ticket: pyotrs.Ticket):
    """!FUTURE! Checks if a ticket can be merged and merges it if possible. (Currently merging or linking tickets is not supported using the API.)
    
    Arguments:
        config {dict} -- The configuration dictionary.
        ticketNumber {str} -- The ticket number to check.
    
    Returns:
        bool -- True if the ticket has been merged, False otherwise.
    """
    ticketNumber = ticket["TicketNumber"]
    ticketState = ticket["State"]
    ticketTitle = ticket["Title"]
    ticketQueue = ticket["Queue"]

    mlog.info("Checking if ticket " + ticketNumber + " can be merged...")
    if ticket["State"] == "merged":
        mlog.warning("Ticket " + ticketNumber + " is already merged.")
        return True

    # Searcch for other tickets with the exact same title:
    mlog.debug("Searching for other tickets with the same title...")
    results = client.ticket_search(state=ticketState, queue=ticketQueue, title=ticketTitle)
    foundOwnTicket = False
    for found_ticket in results:
        if found_ticket["TicketNumber"] == ticketNumber:
            mlog.debug("Found own ticket " + ticketNumber + ". Skipping...")
            foundOwnTicket = True
            continue
        mlog.debug("Found ticket " + found_ticket["TicketNumber"] + " with the same title.")
        # Check if it is already merged itself:
        if found_ticket["State"] == "merged":
            mlog.debug("Ticket " + found_ticket["TicketNumber"] + " is already merged itslef. Skipping...")
            continue
        return False # Currently merging or linking tickets is not supported using the API.

        # TODO: IDEA: Instead of merging, we could also just add a note to the ticket 
        mlog.info("Merging ticket " + ticketNumber + " into ticket " + found_ticket["TicketNumber"] + "...")
        # Merge the ticket:
        client.ticket_merge(ticketNumber, found_ticket["TicketNumber"])

    if not foundOwnTicket:
        mlog.warning("Could not find own ticket " + ticketNumber + " with the same title.")


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
    

def create_client_session() -> pyotrs.Client:
    """Creates a new Znuny OTRS client session.

    Returns:
        pyotrs.Client -- The new client session.
    """
    # Creating Znuny Client
    znuny_url = config["integrations"]["znuny_otrs"]["url"]
    znuny_webservice_name = config["integrations"]["znuny_otrs"]["webservice_name"]
    znuny_username = config["integrations"]["znuny_otrs"]["username"]
    znuny_password = config["integrations"]["znuny_otrs"]["password"]
    znuny_version = config["integrations"]["znuny_otrs"]["version"]
    znuny_verify_certs = config["integrations"]["znuny_otrs"]["verify_certs"]

    TICKET_CONNECTOR_CONFIG_DEFAULT["Name"] = znuny_webservice_name

    # Starting with Znuny 7, the webservice URL changed
    mlog.debug("Creating Znuny client...")
    if znuny_version.startswith("7."):
        client = pyotrs.Client(znuny_url, znuny_username, znuny_password, webservice_config_ticket=TICKET_CONNECTOR_CONFIG_DEFAULT, webservice_path="/znuny/nph-genericinterface.pl/Webservice/", https_verify=znuny_verify_certs)
    else:
        client = pyotrs.Client(znuny_url, znuny_username, znuny_password, webservice_config_ticket=TICKET_CONNECTOR_CONFIG_DEFAULT, webservice_path="/otrs/nph-genericinterface.pl/Webservice/", https_verify=znuny_verify_certs)

    mlog.debug("Znuny client created. Starting session...")
    client.session_create()
    return client


def zs_get_ticket_by_number(ticket_number: str) -> pyotrs.Ticket:
    """Gets a ticket from Znuny by its ticket number.
    
    Arguments:
        ticket_number {str} -- The ticket number of the ticket to get.
    
    Returns:
        pyotrs.Ticket -- The ticket object.
    """
    mlog.info("Getting ticket " + ticket_number + " from Znuny...")
    # TODO: Implement caching
    client = create_client_session()
    ticket = client.ticket_get_by_number(ticket_number)
    return ticket


def zs_create_ticket(detection_report: DetectionReport, DRY_RUN=False, detection_title=None, priority=None, state="new", type_=None, queue_tier="T0", include_context=False, init_note_title=None, init_note_body=None) -> str:
    """Creates a ticket in Znuny.
    
    Arguments:
        config {dict} -- The configuration dictionary.
        detection_report {DetectionReport} -- The detection to create the ticket for.
        title {str} -- The title of the ticket. If not set, the title of the first detection will be used.
        priority {str} -- The priority of the ticket. If not set "normal" will be used.
        state {str} -- The state of the ticket. If not set "new" will be used.
        type_ {str} -- The type of the ticket. If not set "Detection Alert" will be used. (Underscore because 'type' is a reserved keyword in Python)
        queue_tier {str} -- The tier of the queue to create the ticket in. If not set "T0" will be used.
        include_context {bool} -- If set to True, the context of the detection will be added to the ticket. If not set, only the detection will be added. (Not implemented yet).
        init_note_title {str} -- The title of the initial note in the ticket. If not set, the title of the first detection will be used.
        init_note_body {str} -- The body text of the initial note in the ticket. If not set, the description of the first detection will be used (will be appended if set).
    Returns:
        str -- The ticket number of the created ticket.
    """
    if include_context:
        return NotImplementedError # TODO: Implement adding context to ticket on creation
    
    if init_note_body and not init_note_title:
        mlog.critical("init_note_body was set, but init_note_title was not. Aborting ticket creation.")
        return ValueError("init_note_body was set, but init_note_title was not. Aborting ticket creation.")
    
    if not config["integrations"]["znuny_otrs"]["ticketing"]["enabled"]:
        mlog.info("Ticketing is disabled. Not creating ticket.")
        return True

    mlog.info("Creating ticket in Znuny...")

    # Fetching detection report for required information. 
    
    length = len(detection_report.detections)
    if length == 0:
        mlog.critical("The detection report is empty. Aborting ticket creation.")
        return ValueError("The detection report is empty. Aborting ticket creation.")
    
    for detection in detection_report.detections: # Check if all detections are of type Detection
        if not isinstance(detection, Detection):
            mlog.critical("One of the detections of the detection report is not of type Detection. Aborting ticket creation.")
            return TypeError("One of the detections of the detecion report is not of type Detection. Abortung ticket creation.")
        
    # The first detection is used as the ticket will be created for the first detection in a report.
    detection = detection_report.detections[0]

    timestamp = detection.timestamp
    if detection_title is None:
        detection_title = detection.name
    description = detection.description
    severity = detection.severity
    detection_uuid = detection.uuid
    detection_source = detection.source

    # Get offender for ticket title
    if detection.device:
        offender = detection.device.name
    elif detection.indicators["ip"]:
        offender = detection.indicators["ip"][0]
    else:
        mlog.warning("No offender found. Using 'Unknown' as offender.")
        offender = "Unknown"

    # Create client and session
    client = create_client_session()

    mlog.debug("Session started. Creating ticket object...")
    # Creating ticket object
    queue_name = config["integrations"]["znuny_otrs"]["ticketing"]["target_queue"]
    if type_ is None:
        type_ = config["integrations"]["znuny_otrs"]["ticketing"]["default_type"]
    if priority is None:
        priority = config["integrations"]["znuny_otrs"]["ticketing"]["default_priority"]
    
    ticket_title = PRE_TAG + " " + detection_title + " | Offender: " + str(offender)
    znuny_username = config["integrations"]["znuny_otrs"]["username"] 

    ticket_obj = pyotrs.Ticket.create_basic(ticket_title, Queue=queue_name, Type=type_, State="new", Priority=priority, CustomerUser=znuny_username)

    mlog.debug("Ticket object created. Adding initial Note to ticket...")

    # Adding initial article/note to ticket
    if init_note_title is None:
        init_note_title = detection_title
    else:
        init_note_title = init_note_title

    if init_note_body is None:
        init_note_body = description # TODO: Make this more sophisticated
    else:
        init_note_body = init_note_body


    note_title = PRE_TAG + " " + detection_title
    article = pyotrs.Article({"Body": init_note_body,
                              "Charset": "UTF8",
                              "MimeType": "text/html",
                              "Subject": init_note_title,
                              "TimeUnit": 0})


    mlog.debug("Initial note added. Sending ticket to Znuny...")
    if DRY_RUN:
        mlog.warning("Dry run mode is enabled. Not sending actual ticket to Znuny.")
        if init_note_body != None:
            mlog.debug("Ticket: '" + ticket_title + "'\n\n" + str(init_note_body))
        else:
            mlog.debug("Ticket: '" + ticket_title + "'")
        return -1
    else:
        # Sending ticket to Znuny
        ticket = client.ticket_create(ticket_obj, article)

        # Check if ticket creation was successful and return ticket number
        if type(ticket) is bool and not ticket:
                mlog.critical("Ticket creation failed. Znuny did not return a ticket number ('False'). Aborting ticket creation.")
                return SystemError
        try:
            ticket_number = ticket["TicketNumber"]
            detection_report.add_context(ticket)
            return ticket_number
        except KeyError:
            mlog.critical("Ticket creation failed. Znuny did not return a ticket number (Invalid ticket). Aborting ticket creation.")
            return SystemError

    
def zs_add_note_to_ticket(ticket_number: str, mode: str, DRY_RUN=False, raw_title=None, raw_body=None, raw_body_type="text/plain"):
    """Adds a note to an existing ticket in Znuny.

    Arguments:
        ticket_number {str} -- The ticket number of the ticket to add the note to.
        mode {str} -- The mode of the note. Can be "raw", "context" or "analysis". "raw" will add the raw detection to the note. "context" will add the context of the detection to the note. "analysis" will add the analysis of the detection to the note.
        DRY_RUN {bool} -- If set to True, the note will not be added to the ticket. (default: {False})
        raw_title {str} -- The title of the note if mode is set to "raw". (default: {None})
        raw_body {str} -- The body of the note if mode is set to "raw". (default: {None})
        raw_body_type {str} -- The body type of the note if mode is set to "raw". (default: {"text/plain"})

    Keyword Arguments:
        include_context {bool} -- If set to True, the context of the detection will be added to the note. (default: {False})

    Returns:
        int -- The ID of the added note.
    """
    if not config["integrations"]["znuny_otrs"]["ticketing"]["enabled"]:
        mlog.info("Ticketing is disabled. Not adding note to ticket.")
        return True

    if mode not in ["raw", "context", "analysis"]:
        mlog.critical("Invalid mode specified. Aborting note creation.")
        return ValueError("Invalid mode specified. Aborting note creation.")
    
    if mode == "raw" and (raw_title is None or raw_body is None):
        mlog.critical("Raw mode specified but no raw title or body specified. Aborting note creation.")
        return ValueError("Raw mode specified but no raw title or body specified. Aborting note creation.")
    
    if mode != "raw" and (raw_title is not None or raw_body is not None):
        mlog.warning("Raw title or body specified but mode is not set to raw. Ignoring raw title and body.")

    if raw_body_type not in ["text/plain", "text/html"]:
        mlog.critical("Invalid raw body type specified. Aborting note creation.")
        return ValueError("Invalid raw body type specified. Aborting note creation.")
    
    if raw_body_type == "text/html":
        raw_body = str(raw_body)
        raw_body = raw_body.replace("\n", "")

    # Create client and session
    client = create_client_session()

    # Fetching ticket to verify that it exists
    mlog.debug("Fetching ticket from Znuny...")
    if not DRY_RUN:
        ticket = client.ticket_get_by_number(ticket_number)
        if type(ticket) is bool and not ticket:
                mlog.critical("Note creation failed. Znuny did not return a ticket  for the given ticket number ('False'). Aborting note creation.")
                return ValueError("Note creation failed. Znuny did not return a ticket for the given ticket number. Aborting note creation.")
        try:
            _ = ticket.tid
        except KeyError:
            mlog.critical("Note creation failed. Znuny did not return a ticket for the given ticket number  (Invalid ticket). Aborting note creation.")
            return ValueError("Note creation failed. Znuny did not return a ticket for the given ticket number. Aborting note creation.")

    # Prepare Article dictionary
    if mode == "raw":
        note_title = PRE_TAG + " " + raw_title
        note_body = raw_body
        note_body_type = raw_body_type
    elif mode == "context":
        return NotImplementedError("Context mode is not implemented yet.")
    elif mode == "analysis":
        return NotImplementedError("Analysis mode is not implemented yet.")
    
    article = pyotrs.Article({"Body": note_body,
                                "Charset": "UTF8",
                                "MimeType": note_body_type,
                                "Subject": note_title,
                                "TimeUnit": 0})
    
    mlog.debug("Adding note to ticket...")
    if DRY_RUN:
        mlog.warning("Dry run mode is enabled. Not adding actual note to ticket.")
        if note_body != None:
            mlog.debug("Note: '" + note_title + "'\n\n" + note_body)
        else:
            mlog.debug("Note: '" + note_title)
        return -1
    else:
        # Adding note to ticket
        result = client.ticket_update(ticket.tid, article)

        # Check if note was added successfully
        try:
            return result["ArticleID"]
        except KeyError:
            mlog.critical("Note creation failed. Znuny did not return a note ID. Aborting note creation.")
            return SystemError("Note creation failed. Znuny did not return a note ID. Aborting note creation.")



if __name__ == "__main__":
    # This integration should not be called directly besides running the integration setup!
    main()