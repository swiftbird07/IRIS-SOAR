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
# [ ] Ticketing: Adding notes to tickets
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

# For new detections:
from lib.class_helper import Rule, Detection, ContextProcess, ContextFlow

# For context for detections (remove unused types):
from lib.class_helper import DetectionReport, ContextFlow, ContextLog, ContextProcess, cast_to_ipaddress
from lib.generic_helper import deep_get, get_from_cache, add_to_cache

PRE_TAG = "[ZSOAR Detection]" # Tag before the title of the ticket (without spaces)

cfg = Config().cfg
log_level_file = cfg["integrations"]["znuny_otrs"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["znuny_otrs"]["logging"]["log_level_stdout"]
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

    set_int(intgr, "url", "url", "Enter the URL to connec to to Znuny", additional_info="Example: https://tickets.example.com")

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

def zs_create_ticket(config, detectionReport: DetectionReport, TEST=False, detection_title=None, priority="normal", state="new", type_="Detection Alert", queue_tier="T0", include_context=False, init_note_title=None, init_note_body=None) -> str:
    """Creates a ticket in Znuny.
    
    Arguments:
        config {dict} -- The configuration dictionary.
        detectionReport {DetectionReport} -- The detection to create the ticket for.
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

    if TEST:
        mlog.info("TEST: Creating ticket in Znuny...")
        return NotImplementedError # TODO: Implement Tests
    
    mlog.info("Creating ticket in Znuny...")

    # Fetching detection report for required information. 
    
    len = detectionReport.len()
    if len == 0:
        mlog.critical("The detection report is empty. Aborting ticket creation.")
        return ValueError("The detection report is empty. Aborting ticket creation.")
    
    for detection in detectionReport.detections: # Check if all detections are of type Detection
        if not isinstance(detection, Detection):
            mlog.critical("One of the detections of the detection report is not of type Detection. Aborting ticket creation.")
            return TypeError("One of the detections of the detecion report is not of type Detection. Abortung ticket creation.")
        
    # The first detection is used as the ticket will be created for the first detection in a report.
    detection = detectionReport.detections[0]

    timestamp = detection.timestamp
    if detection_title is None:
        detection_title = detection.name
    description = detection.description
    severity = detection.severity
    detection_uuid = detection.uuid
    detection_type = detection.type
    detection_source = detection.source

    # Get offender for ticket title
    if detection.device:
        offender = detection.device.name
    elif detection.indicators["ip"]:
        offender = detection.indicators["ip"][0]
    else:
        mlog.warning("No offender found. Using 'Unknown' as offender.")
        offender = "Unknown"

    # Creating Znuny Client
    znuny_url = config["integrations"]["znuny_otrs"]["url"]
    znuny_webservice_name = config["integrations"]["znuny_otrs"]["webservice_name"]
    znuny_username = config["integrations"]["znuny_otrs"]["username"]
    znuny_password = config["integrations"]["znuny_otrs"]["password"]
    znuny_version = config["integrations"]["znuny_otrs"]["version"]
    znuny_verify_certs = config["integrations"]["znuny_otrs"]["verify_certs"]

    # Starting with Znuny 7, the webservice URL changed
    mlog.debug("Creating Znuny client...")
    if znuny_version.startswith("7."):
        client = pyotrs.Client(znuny_url, znuny_username, znuny_password, webservice_config_ticket=znuny_webservice_name, webservice_path="/znuny/nph-genericinterface.pl", https_verify=znuny_verify_certs)
    else:
        client = pyotrs.Client(znuny_url, znuny_username, znuny_password, webservice_config_ticket=znuny_webservice_name, https_verify=znuny_verify_certs)

    mlog.debug("Znuny client created. Starting session...")
    client.session_create()

    mlog.debug("Session started. Creating ticket...")

    # Creating ticket object
    queue_name = config["integrations"]["znuny_otrs"]["ticketing"]["target_queue"]
    ticket_title = PRE_TAG + " " + detection_title + " | Offender: " + offender 
    ticket = pyotrs.Ticket.create_basic(ticket_title, Queue=queue_name, Type=type_, State="new", Priority=severity, CustomerUser=znuny_username)

    # Check if ticket creation was successful
    if ticket is None or ticket.ticket_id is None:
        mlog.critical("Ticket creation failed.")
        return

    mlog.debug("Ticket created. Adding initial Note to ticket...")

    # Adding initial article/note to ticket
    ticket_id = ticket.ticket_id
    if init_note_title is None:
        init_note_title = detection_title
    else:
        init_note_title = init_note_title
    if init_note_body is None:
        init_note_body = description
    else:
        init_note_body = init_note_body + "\n\n" + description
    note_title = PRE_TAG + " " + detection_title
    article = pyotrs.Article(title=note_title, body=init_note_body, content_type="text/plain", charset="utf8")
    ticket.add_article(article)

    mlog.debug("Initial note added. Sending ticket to Znuny...")
    # Sending ticket to Znuny
    ticket.send()
    




# TODO: Ticket creation [X] (untested)
# TODO: - Ticket Auto-Merging
# TODO: - Ticket Auto-Linking
# TODO: Note creation to ticket
# TODO: Provide new detections
# TODO: Provide context for detections (CMDB, Ticket, etc.)

    





if __name__ == "__main__":
    # This integration should not be called directly besides running the integration setup!
    main()