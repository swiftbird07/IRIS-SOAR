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
import traceback

# For new detections:
from lib.class_helper import Rule, Detection, ContextProcess, ContextFlow

# For context for detections (remove unused types):
from lib.class_helper import DetectionReport, ContextFlow, ContextLog, ContextProcess, AuditLog
from lib.generic_helper import get_unique, format_results, del_none_from_dict

PRE_TAG = "[ZSOAR]"  # Tag before the title of the ticket (without spaces)

TICKET_CONNECTOR_CONFIG_DEFAULT = {
    "Name": "GenericTicketConnectorREST",
    "Config": {
        "SessionCreate": {"RequestMethod": "POST", "Route": "/Session", "Result": "SessionID"},
        "AccessTokenCreate": {"RequestMethod": "POST", "Route": "/Session", "Result": "AccessToken"},
        "SessionGet": {"RequestMethod": "GET", "Route": "/Session/:SessionID", "Result": "SessionData"},
        "TicketCreate": {"RequestMethod": "POST", "Route": "/Ticket", "Result": "TicketID"},
        "TicketGet": {"RequestMethod": "GET", "Route": "/Ticket/:TicketID", "Result": "Ticket"},
        "TicketGetList": {"RequestMethod": "GET", "Route": "/TicketList", "Result": "Ticket"},
        "TicketSearch": {"RequestMethod": "GET", "Route": "/Ticket", "Result": "TicketID"},
        "TicketUpdate": {"RequestMethod": "PATCH", "Route": "/Ticket/:TicketID", "Result": "TicketID"},
    },
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
    return NotImplementedError  # TODO: Implement


def zs_provide_context_for_detections(
    config, detection_report: DetectionReport, required_type: type, TEST=False, UUID=None, UUID_is_parent=False, maxContext=50
) -> Union[ContextFlow, ContextLog, ContextProcess]:
    return NotImplementedError  # TODO: Implement


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
        return False  # Currently merging or linking tickets is not supported using the API.

        # TODO: IDEA: Instead of merging, we could also just add a note to the ticket
        mlog.info("Merging ticket " + ticketNumber + " into ticket " + found_ticket["TicketNumber"] + "...")
        # Merge the ticket:
        client.ticket_merge(ticketNumber, found_ticket["TicketNumber"])

    if not foundOwnTicket:
        mlog.warning("Could not find own ticket " + ticketNumber + " with the same title.")


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
        client = pyotrs.Client(
            znuny_url,
            znuny_username,
            znuny_password,
            webservice_config_ticket=TICKET_CONNECTOR_CONFIG_DEFAULT,
            webservice_path="/znuny/nph-genericinterface.pl/Webservice/",
            https_verify=znuny_verify_certs,
        )
    else:
        client = pyotrs.Client(
            znuny_url,
            znuny_username,
            znuny_password,
            webservice_config_ticket=TICKET_CONNECTOR_CONFIG_DEFAULT,
            webservice_path="/otrs/nph-genericinterface.pl/Webservice/",
            https_verify=znuny_verify_certs,
        )

    mlog.debug("Znuny client created. Starting session...")
    client.session_create()
    return client


def create_auto_detection(
    mode, detection_report: DetectionReport, detection: Detection, playbook_name, playbook_step, DRY_RUN=False, ticket_number=None
):
    if mode == "existing_ticket" and not ticket_number:
        raise ValueError("Ticket number must be specified when using existing_ticket mode.")

    if mode == "new_ticket":
        current_action = AuditLog(playbook_name, playbook_step, "Create Ticket", "Creating ticket for detection.")
        detection_report.update_audit(current_action, logger=mlog)
    elif mode == "existing_ticket":
        current_action = AuditLog(playbook_name, playbook_step, "Update Ticket", "Updating ticket with a new detection.")
        detection_report.update_audit(current_action, logger=mlog)
    else:
        raise ValueError("Invalid mode specified.")

    init_title = f"Detection: {detection.name} ({detection.uuid})"
    init_body = f"<h2>Detection: {detection.name} ({detection.uuid})</h2><br><br><br>"
    for k, v in detection.__dict__().items():
        if type(v) == list and len(v) == 1:
            v = v[0]

        try:
            v = json.dumps(del_none_from_dict(json.loads(str(v))), indent=4, sort_keys=False, default=str)
            v = v.replace("\n", "<br>")
        except:
            v = str(v)
        init_body += f"<h3>{k}:</h3> <font size='+2'>{v}</font><br><br>"

    if mode == "new_ticket":
        # Create ticket recursively by calling this function again with auto_detection_note set to False and init_note_title and init_note_body set to the parsed values.
        ticket_number = zs_create_ticket(
            detection_report, DRY_RUN, auto_detection_note=False, init_note_title=init_title, init_note_body=init_body
        )
        if ticket_number is None or not ticket_number:
            mlog.error(f"Failed to create ticket for detection: '{detection.name}' ({detection.uuid})")
            detection_report.update_audit(
                current_action.set_error(message="Failed to create ticket for detection (No ticket_number returned)."),
                logger=mlog,
            )
            return detection_report
        else:
            mlog.info(
                f"Successfully created ticket for detection: '{detection.name}' ({detection.uuid}) with ticket number: {ticket_number}"
            )
            detection_report.update_audit(
                current_action.set_successful(
                    message=f"Successfully created ticket for detection with ticket number: {ticket_number}",
                    ticket_number=ticket_number,
                ),
                logger=mlog,
            )
        return ticket_number

    elif mode == "existing_ticket":
        zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, init_title, init_body)
        return


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
    ticket = client.ticket_get_by_number(ticket_number, articles=True)
    return ticket


def zs_create_ticket(
    detection_report: DetectionReport,
    detection=None,
    DRY_RUN=False,
    priority=None,
    state="new",
    type_=None,
    queue_tier="T0",
    auto_detection_note=False,
    playbook_name=None,
    playbook_step=None,
    include_context=False,
    init_note_title=None,
    init_note_body=None,
) -> str:
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
        auto_detection_note {bool} -- If set to True, a note with the detection information will be automatically parsed and added to the ticket. If not set, init_note_title and init_note_body will be used.
        PB_NAME {str} -- The name of the playbook that created the ticket (only used for auto_detection_note).
        init_note_title {str} -- The title of the initial note in the ticket. If not set, the title of the first detection will be used (will be ignored if auto_detection_note is set).
        init_note_body {str} -- The body text of the initial note in the ticket. If not set, the description of the first detection will be used (will be ignored if auto_detection_note is set).

    Returns:
        str -- The ticket number of the created ticket.
    """
    if include_context:
        return NotImplementedError  # TODO: Implement adding context to ticket on creation

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

    for detection in detection_report.detections:  # Check if all detections are of type Detection
        if not isinstance(detection, Detection):
            mlog.critical("One of the detections of the detection report is not of type Detection. Aborting ticket creation.")
            return TypeError("One of the detections of the detecion report is not of type Detection. Abortung ticket creation.")

    # The first detection is used as the ticket will be created for the first detection in a report.
    detection = detection_report.detections[0]

    timestamp = detection.timestamp
    detection_title = detection_report.get_title()
    description = detection.description
    severity = detection.severity
    detection_uuid = detection.uuid
    detection_source = detection.source

    # Get offender for ticket title
    if detection.device and detection.device.name != "" and detection.device.name != None:
        offender = detection.device.name
    elif detection.device and str(detection.device.local_ip) != "":
        offender = detection.device.local_ip
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

    ticket_obj = pyotrs.Ticket.create_basic(
        ticket_title, Queue=queue_name, Type=type_, State="new", Priority=priority, CustomerUser=znuny_username
    )

    mlog.debug("Ticket object created. Adding initial Note to ticket...")

    # Adding initial article/note to ticket

    # If auto_detection_note is set, the detection information will be parsed and added to the ticket.
    if auto_detection_note:
        mode = "new_ticket"
        ticket_number = create_auto_detection(mode, detection_report, detection, playbook_name, playbook_step, DRY_RUN)
        return ticket_number

    note_title = PRE_TAG + " " + detection_title
    article = pyotrs.Article(
        {"Body": init_note_body, "Charset": "UTF8", "MimeType": "text/html", "Subject": note_title, "TimeUnit": 0}
    )

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
            mlog.critical(
                "Ticket creation failed. Znuny did not return a ticket number (Invalid ticket). Aborting ticket creation."
            )
            return SystemError


def zs_add_note_to_ticket(
    ticket_number: str,
    mode: str,
    DRY_RUN=False,
    raw_title=None,
    raw_body=None,
    raw_body_type="text/plain",
    playbook_name=None,
    playbook_step=None,
    detection_report: DetectionReport = None,
    detection: Detection = None,
    detection_contexts=None,
    other_contexts=None,
    parents=None,
    children=None,
    tree=None,
    file_names=None,
    visible_for_customer=True,
    gather_type=None,
):
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

    if mode not in [
        "raw",
        "analysis",
        "context_process",
        "context_file",
        "context_network",
        "context_registry",
        "detection",
        "context_log",
    ]:
        mlog.critical(f"Invalid mode specified: '{str(mode)}'. Aborting note creation.")
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
            mlog.critical(
                "Note creation failed. Znuny did not return a ticket  for the given ticket number ('False'). Aborting note creation."
            )
            return ValueError(
                "Note creation failed. Znuny did not return a ticket for the given ticket number. Aborting note creation."
            )
        try:
            _ = ticket.tid
        except KeyError:
            mlog.critical(
                "Note creation failed. Znuny did not return a ticket for the given ticket number  (Invalid ticket). Aborting note creation."
            )
            return ValueError(
                "Note creation failed. Znuny did not return a ticket for the given ticket number. Aborting note creation."
            )

    # Prepare Article dictionary
    if mode == "raw":
        note_title = PRE_TAG + " " + raw_title
        note_body = raw_body
        note_body_type = raw_body_type

    elif mode == "context_process":
        # Create a note for Process Context
        try:
            if not playbook_name or not detection_report or not detection:
                raise ValueError("Missing arguments for context_process note creation.")

            process_names = detection_contexts
            process_tree = tree
            body = ""

            current_action = AuditLog(
                playbook_name, playbook_step, "Create Note - Process Context", "Creating note for processes in detection."
            )
            detection_report.update_audit(current_action, logger=mlog)

            if not detection.process and gather_type != "time range":
                mlog.warning(f"Detection has no process. Skipping note creation.")
                detection_report.update_audit(
                    current_action.set_warning(warning_message=f"Detection has no process. Skipping note creation."), logger=mlog
                )
            else:
                # Replace "\n" by "<br" in process_tree
                if process_tree:
                    process_tree = process_tree.replace("\n", "<br>")
                    process_tree = process_tree.replace("    ", "&emsp;")

                title = "Context: Processes"
                if gather_type and gather_type == "time range":
                    title += " [time range]"
                else:
                    title += " [direct]"
                    body += f"<br><br><h2>Process Context:</h2><br><br>"
                    body += f"<br><br><h3>Process Tree:</h3><br>{process_tree if process_tree else 'No process tree available.'}<br><br>"
                    body += f"<br><br><h3>Context regarding detected Process:</h3><br><br>"
                    body += f"Process Name: {detection.process.process_name if detection.process else 'N/A'}<br>"
                    body += f"Process ID: {detection.process.process_id}<br>"
                    body += f"Process Path: {detection.process.process_path}<br>"
                    body += f"Process Command Line: {detection.process.process_command_line}<br>"
                    body += f"Process SHA256: {detection.process.process_sha256}<br>"

                    body += f"<br><br><h3>List of all reported process names: </h3><br><br>"
                    body += f"{get_unique(process_names)}"

                    body += f"<br><br><h3>Parent Processes:<br><br><h3>"
                    body += format_results(parents, "html", group_by="process_id")

                    body += f"<br><br><h3>Child Processes:</h3><br>"
                    body += "<br>" + format_results(children, "html", group_by="process_id")

                body += "<br><br><h3>Complete Process Timeline:</h3><br>"
                body += "<br>" + format_results(detection_report.context_processes, "html", group_by="")

                note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, title, body, "text/html")
                if type(note_id) is not int:
                    mlog.warning(f"Failed to create note for processes in detection.")
                    detection_report.update_audit(
                        current_action.set_error(
                            warning_message=f"Failed to create note for processes in detection (returned).", exception=note_id
                        ),
                        logger=mlog,
                    )
                else:
                    mlog.info(
                        f"Successfully created note for processes in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}"
                    )
                    detection_report.update_audit(
                        current_action.set_successful(
                            message=f"Successfully created note for processes in detection with note id: {note_id}",
                            ticket_number=ticket_number,
                        ),
                        logger=mlog,
                    )

        except Exception as e:
            mlog.error(
                f"Failed to create note for processes in detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
            )
            detection_report.update_audit(
                current_action.set_error(message=f"Failed to create note for processes in detection (catched).", exception=e),
                logger=mlog,
            )
        return 1

    elif mode == "context_network":
        # Create a note for Network Context
        try:
            if not playbook_name or not detection_report or not detection:
                raise ValueError("Missing arguments for context_process note creation.")

            detected_process_flows = detection_contexts
            context_process_flows = other_contexts

            if not detected_process_flows:
                detected_process_flows = []

            if not context_process_flows:
                context_process_flows = []

            body = ""

            current_action = AuditLog(
                playbook_name, playbook_step, "Create Note - Network Context", "Creating note for network flows in the detection."
            )
            detection_report.update_audit(current_action, logger=mlog)

            note_title = "Context: Network Flows"
            if gather_type and gather_type == "time range":
                note_title += " [time range]"
            else:
                note_title += " [direct]"

            # Check if any network flows were found
            if len(detected_process_flows) == 0 and len(context_process_flows) == 0 and len(detection_report.context_flows) == 0:
                detection_report.update_audit(
                    current_action.set_warning(warning_message=f"Found no network flows for detection."), logger=mlog
                )
                note_title += " (empty)"

            if not gather_type or gather_type == "direct":
                body += f"<br><br><h2>Network Context:</h2><br><br>"
                if detection.process:
                    body += f"<h3>Network Flows of detected Process '{detection.process.process_name}' ({detection.process.process_id}):</h3><br><br>"
                else:
                    body += f"<h3>Network Flows of Detection:</h3><br><br>"
                body += format_results(detected_process_flows, "html", group_by="")

                body += f"<br><br><h3>List of all reported IPs and domains: </h3><br><br>"
                body += str(detection_report.indicators["ip"]) + "<br>" + str(detection_report.indicators["domain"]) + "<br><br>"

                if context_process_flows and len(context_process_flows) > 0:
                    body += f"<br><br><h3>Network Flows of other Processes (grouped by process):</h3><br><br>"
                    body += format_results(context_process_flows, "html", group_by="process_id")

            body += "<br><br><h3>Complete Network Timeline:</h3><br>"
            body += "<br>" + format_results(detection_report.context_flows, "html", group_by="")

            note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, body, "text/html")
            if type(note_id) is not int:
                mlog.warning(f"Failed to create note for network in detection.")
                detection_report.update_audit(
                    current_action.set_error(
                        warning_message=f"Failed to create note for network in detection (returned).", exception=note_id
                    ),
                    logger=mlog,
                )
            else:
                mlog.info(
                    f"Successfully created note for network in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}"
                )
                current_action.playbook_done = True
                detection_report.update_audit(
                    current_action.set_successful(
                        message=f"Successfully created note for network in detection with note id: {note_id}",
                        ticket_number=ticket_number,
                    ),
                    logger=mlog,
                )
        except Exception as e:
            mlog.error(
                f"Failed to create note for network in detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
            )
            detection_report.update_audit(
                current_action.set_error(message=f"Failed to create note for network in detection (catched).", exception=e),
                logger=mlog,
            )
        return 1

    elif mode == "context_file":
        # Create a note for File Events
        try:
            if not playbook_name or not detection_report or not detection:
                raise ValueError("Missing arguments for context_process note creation.")

            detected_process_file_events = detection_contexts
            context_processes_file_events = other_contexts

            if not detected_process_file_events:
                detected_process_file_events = []

            if not context_processes_file_events:
                context_processes_file_events = []

            body = ""

            current_action = AuditLog(
                playbook_name, playbook_step, "Create Note - File Events", "Creating note for file events in the detection."
            )
            detection_report.update_audit(current_action, logger=mlog)
            note_title = "Context: File Events"
            if gather_type and gather_type == "time range":
                note_title += " [time range]"
            else:
                note_title += " [direct]"

            # Check if any file events were found
            if (
                len(detected_process_file_events) == 0
                and len(context_processes_file_events) == 0
                and len(detection_report.context_files) == 0
            ):
                detection_report.update_audit(
                    current_action.set_warning(warning_message=f"Found no file events for detection."), logger=mlog
                )
                note_title += " (empty)"

            if not gather_type or gather_type == "direct":
                body += f"<br><br><h2>File Event Context:</h2><br><br>"
                if detection.process:
                    body += f"<h3>File Events of detected Process '{detection.process.process_name}' ({detection.process.process_id}):</h3><br><br>"
                else:
                    body += f"<h3>File Events of Detection:</h3><br><br>"
                body += format_results(detected_process_file_events, "html", group_by="")

                if context_processes_file_events and len(context_processes_file_events) > 0:
                    body += f"<br><br><h3>List of all reported files: </h3><br><br>"
                    body += f"{get_unique(file_names)}"
                    body += f"<br><br><h3>File Events of other Processes (grouped by process):</h3><br><br>"
                    body += format_results(context_processes_file_events, "html", group_by="process_id")

            body += "<br><br><h3>Complete File Event Timeline:</h3><br>"
            body += "<br>" + format_results(detection_report.context_files, "html", group_by="")

            note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, body, "text/html")
            if type(note_id) is not int:
                mlog.warning(f"Failed to create note for file events in detection.")
                detection_report.update_audit(
                    current_action.set_error(
                        warning_message=f"Failed to create note for file events in detection (returned).", exception=note_id
                    ),
                    logger=mlog,
                )
            else:
                mlog.info(
                    f"Successfully created note for file events in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}"
                )
                detection_report.update_audit(
                    current_action.set_successful(
                        message=f"Successfully created note for file events in detection with note id: {note_id}",
                        ticket_number=ticket_number,
                    ),
                    logger=mlog,
                )
        except Exception as e:
            mlog.error(
                f"Failed to create note for file events in detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
            )
            detection_report.update_audit(
                current_action.set_error(message=f"Failed to create note for file events in detection (catched).", exception=e),
                logger=mlog,
            )
        return 1

    elif mode == "context_registry":
        # Create a note for Registry Events
        try:
            if not playbook_name or not detection_report or not detection:
                raise ValueError("Missing arguments for context_process note creation.")

            detected_process_registry_events = detection_contexts
            context_processes_registry_events = other_contexts
            body = ""

            if detected_process_registry_events is None:
                detected_process_registry_events = []

            if context_processes_registry_events is None:
                context_processes_registry_events = []

            current_action = AuditLog(
                playbook_name,
                playbook_step,
                "Create Note - Registry Events",
                "Creating note for registry events in the detection.",
            )
            detection_report.update_audit(current_action, logger=mlog)
            note_title = "Context: Registry Events"
            if gather_type and gather_type == "time range":
                note_title += " [time range]"
            else:
                note_title += " [direct]"

            # Check if any registry events were found
            if (
                len(detected_process_registry_events) == 0
                and len(context_processes_registry_events) == 0
                and len(detection_report.context_registries) == 0
            ):
                mlog.warning(f"Found no registry events for detection.")
                detection_report.update_audit(
                    current_action.set_warning(warning_message=f"Found no registry events for detection."), logger=mlog
                )
                note_title += " (empty)"

            if not gather_type or gather_type == "direct":
                body += f"<br><br><h2>Registry Event Context:</h2><br><br>"
                if detection.process:
                    body += f"<h3>Registry Events of detected Process '{detection.process.process_name}' ({detection.process.process_id}):</h3><br><br>"
                else:
                    body += f"<h3>Registry Events of detected Process <N/A>:</h3><br><br>"
                body += format_results(detected_process_registry_events, "html", group_by="")
                body += f"<br><br><h3>Registry Events of other Processes (grouped by process):</h3><br><br>"
                body += format_results(context_processes_registry_events, "html", group_by="process_id")
            body += f"<br><br><h3>Complete Registry Event Timeline:</h3><br>"
            body += "<br>" + format_results(detection_report.context_registries, "html", group_by="")

            note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, body, "text/html")
            if type(note_id) is not int:
                mlog.warning(f"Failed to create note for registry events in detection.")
                detection_report.update_audit(
                    current_action.set_error(
                        warning_message=f"Failed to create note for registry events in detection (returned).", exception=note_id
                    ),
                    logger=mlog,
                )
            else:
                mlog.info(
                    f"Successfully created note for registry events in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}"
                )
                current_action.playbook_done = True
                detection_report.update_audit(
                    current_action.set_successful(
                        message=f"Successfully created note for registry events in detection with note id: {note_id}",
                        ticket_number=ticket_number,
                    ),
                    logger=mlog,
                )

        except Exception as e:
            mlog.error(
                f"Failed to create note for registry events in detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
            )
            detection_report.update_audit(
                current_action.set_error(
                    message=f"Failed to create note for registry events in detection (catched).", exception=e
                ),
                logger=mlog,
            )
        return 1

    elif mode == "context_log":
        # Create a note for Log Events
        try:
            if not playbook_name or not detection_report or not detection:
                raise ValueError("Missing arguments for context_process note creation.")

            detected_process_log_events = detection_contexts
            context_processes_log_events = other_contexts
            body = ""

            current_action = AuditLog(
                playbook_name,
                playbook_step,
                "Create Note - Log Events",
                "Creating note for log events in the detection.",
            )
            detection_report.update_audit(current_action, logger=mlog)
            note_title = "Context: Log Events"
            if gather_type and gather_type == "time range":
                note_title += " [time range]"
            else:
                note_title += " [direct]"

            # Check if any log events were found
            if (
                detected_process_log_events is None
                and len(context_processes_log_events) == 0
                and len(detection_report.context_logs) == 0
            ):
                mlog.warning(f"Found no log events for detection.")
                detection_report.update_audit(
                    current_action.set_warning(warning_message=f"Found no log events for detection."), logger=mlog
                )
                note_title += " (empty)"

            if not gather_type or gather_type == "direct":
                body += f"<br><br><h2>Log Event Context:</h2><br><br>"
                if detection.process:
                    body += f"<h3>Log Events of detected Process '{detection.process.process_name}' ({detection.process.process_id}):</h3><br><br>"
                else:
                    body += f"<h3>Log Events of Detection:</h3><br><br>"
                body += format_results(detected_process_log_events, "html", group_by="")

                if context_processes_log_events and len(context_processes_log_events) > 0:
                    body += f"<br><br><h3>Log Events of other Processes (grouped by process):</h3><br><br>"
                    body += format_results(context_processes_log_events, "html", group_by="process_id")

            body += f"<br><br><h3>Complete Log Event Timeline:</h3><br>"
            body += "<br>" + format_results(detection_report.context_logs, "html", group_by="")

            note_id = zs_add_note_to_ticket(ticket_number, "raw", DRY_RUN, note_title, body, "text/html")
            if type(note_id) is not int:
                mlog.warning(f"Failed to create note for log events in detection.")
                detection_report.update_audit(
                    current_action.set_error(
                        warning_message=f"Failed to create note for log events in detection (returned).", exception=note_id
                    ),
                    logger=mlog,
                )
            else:
                mlog.info(
                    f"Successfully created note for log events in detection: '{detection.name}' ({detection.uuid}) with note id: {note_id}"
                )
                current_action.playbook_done = True
                detection_report.update_audit(
                    current_action.set_successful(
                        message=f"Successfully created note for log events in detection with note id: {note_id}",
                        ticket_number=ticket_number,
                    ),
                    logger=mlog,
                )

        except Exception as e:
            mlog.error(
                f"Failed to create note for log events in detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
            )
            detection_report.update_audit(
                current_action.set_error(message=f"Failed to create note for log events in detection (catched).", exception=e),
                logger=mlog,
            )
        return 1

    elif mode == "analysis":
        return NotImplementedError("Analysis mode is not implemented yet.")

    elif mode == "detection":
        create_auto_detection(
            "existing_ticket", detection_report, detection, playbook_name, playbook_step, DRY_RUN, ticket_number
        )
        return 1

    article = pyotrs.Article(
        {
            "Body": note_body,
            "Charset": "UTF8",
            "MimeType": note_body_type,
            "Subject": note_title,
            "TimeUnit": 0,
            "IsVisibleForCustomer": 0 if visible_for_customer == False else 1,
        },
    )

    mlog.debug("Adding note to ticket...")
    if DRY_RUN:
        mlog.warning("Dry run mode is enabled. Not adding actual note to ticket.")
        if note_body != None:
            mlog.debug("Note: '" + note_title + "'\n\n" + note_body)
        else:
            mlog.debug("Note: '" + note_title)
        return 123
    else:
        # Adding note to ticket
        result = client.ticket_update(ticket.tid, article)

        # Check if note was added successfully
        try:
            return result["ArticleID"]
        except KeyError:
            mlog.critical("Note creation failed. Znuny did not return a note ID. Aborting note creation.")
            return Exception("Note creation failed. Znuny did not return a note ID. Aborting note creation.")


def zs_update_ticket_title(detection_report: DetectionReport, title, DRY_RUN=False):
    """Updates the title of a ticket.

    Args:
        ticket_number (int): Ticket number of the ticket to update.
        title (str): New title of the ticket.
        DRY_RUN (bool, optional): If true, no actual changes will be made. Defaults to False.

    Returns:
        int: Ticket number of the updated ticket.
    """
    if len(title) > 200:
        mlog.warning(f"Ticket title '{title}' is longer than 200 characters. Truncating title to 197 characters + '...'.")
        title = title[:197] + "..."

    ticket_number = detection_report.get_ticket_number()
    ticket_id = detection_report.get_ticket_id()

    mlog.debug(f"Updating title of ticket {ticket_number} to '{title}'")
    # Create client and session
    client = create_client_session()

    if DRY_RUN:
        mlog.warning("Dry run mode is enabled. Not updating actual ticket.")
        return ticket_number
    else:
        # Updating ticket title
        result = client.ticket_update(ticket_id=ticket_id, Title=title)

        # Check if title was updated successfully
        try:
            return result["TicketNumber"]
        except KeyError:
            mlog.critical("Title update failed. Znuny did not return a ticket number. Aborting title update.")
            return Exception("Title update failed. Znuny did not return a ticket number. Aborting title update.")


if __name__ == "__main__":
    # This integration should not be called directly besides running the integration setup!
    main()
