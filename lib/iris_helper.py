# IRIS-SOAR
# Created by: Martin Offermann
# This helper module is used to provide DFIR-IRIS specific functions.

from dfir_iris_client.session import ClientSession
from dfir_iris_client.alert import Alert
from dfir_iris_client.case import Case

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
from lib.generic_helper import del_none_from_dict, dict_get

import traceback

# Prepare the logger
cfg = config_helper.Config().cfg
config = cfg["integrations"]["dfir-iris"]
log_level_file = config["logging"]["log_level_file"]
log_level_stdout = config["logging"]["log_level_stdout"]
mlog = logging_helper.Log("integrations.dfir-iris", log_level_file, log_level_stdout)

IRSOAR_USE_TEMPLATE = False
IRSOAR_TEMPLATE = None


def get_cases_by_title(title, partial_match=False):
    """Returns a list of cases that match the title.

    Args:
        str (str): The title of the case
        partial_match (bool, optional): If True, the title only needs to be a part of the case title. Defaults to False.

    Returns:
        list: A list of cases or False if an error occured
    """
    try:
        case_list = []
        if type(title) != str:
            mlog.error(f"get_cases_by_title() was called with a non-string argument: {title}")
            return False
        title = title.lower()

        # Initiate a session with our API key and host. Session stays the same during all the script run.
        session = ClientSession(
            apikey=config["api_key"],
            host=config["url"],
            ssl_verify=False,
        )

        # Get all cases
        # TODO: Ask if cases can be search more generally
        case = Case(session=session)
        response = case.list_cases()
        if not response.is_success():
            mlog.error(f"Could not get cases from IRIS: {response.get_error_message()}")
            return False

        cases = response.get_data()
        for case in cases:
            case_name = case["case_name"].lower()
            if case_name == title:
                case_list.append(case)

            elif partial_match == True:
                if title in case_name:
                    case_list.append(case)

    except Exception as e:
        mlog.error(f"Could not get cases from IRIS: {traceback.format_exc()}")
        return False

    return case_list


def update_alert_state(alert_id, state):
    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(
        apikey=config["api_key"],
        host=config["url"],
        ssl_verify=False,
    )

    # Get the alert
    alert_obj = Alert(session=session)

    if type(state) == str:
        state = state.lower()
        if state == "open":
            state_id = 1
        elif state == "closed":
            state_id = 2
    elif type(state) == int:
        state_id = state
    else:
        mlog.error(f"update_alert_state() was called with a non-string and non-int state argument: {state}")
        return False

    alert_obj.update_alert(alert_id, {"alert_status_id": state_id})
    return True


def merge_alert_to_case(alert_id, case_number, iocs=None, assets=None, note=None):
    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(
        apikey=config["api_key"],
        host=config["url"],
        ssl_verify=False,
    )

    # Transform IOCs and Assets to the correct format
    iocs = []
    assets = []

    # Get the alert
    alert = Alert(session=session)

    for ioc in dict_get(alert.get_alert(alert_id).get_data(), "iocs", default=[]):
        iocs.append(ioc["ioc_uuid"])

    for asset in dict_get(alert.get_alert(alert_id).get_data(), "assets", default=[]):
        assets.append(asset["asset_uuid"])

    alert.merge_alert(alert_id, case_number, iocs, assets, note, True)
    return True


def escalate_alert(alert_id, title, note=None, tags=None):
    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(
        apikey=config["api_key"],
        host=config["url"],
        ssl_verify=False,
    )

    if IRSOAR_USE_TEMPLATE:
        template = IRSOAR_TEMPLATE  # TODO: Implement this
    else:
        template = None

    # Get the alert
    alert = Alert(session=session)

    # Transform IOCs and Assets to the correct format
    iocs = []
    assets = []

    for ioc in dict_get(alert.get_alert(alert_id).get_data(), "iocs", default=[]):
        iocs.append(ioc["ioc_uuid"])

    for asset in dict_get(alert.get_alert(alert_id).get_data(), "assets", default=[]):
        assets.append(asset["asset_uuid"])

    response = alert.escalate_alert(alert_id, iocs, assets, note, title, tags, template, True)
    if not response.is_success():
        mlog.error(f"Could not escalate alert to case: {response.log_error()}")
        return False

    return response.get_data()["case_id"]


def add_note_to_alert(alert_id, msg):
    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(
        apikey=config["api_key"],
        host=config["url"],
        ssl_verify=False,
    )

    # Get the alert
    alert = Alert(session=session)
    current_alert = alert.get_alert(alert_id)
    if not current_alert.is_success():
        mlog.error(f"Could not get alert from IRIS: {current_alert.log_error()}")
        return False
    current_note = current_alert.get_data_field("alert_note")

    alert.update_alert(alert_id, {"alert_note": current_note + "\n" + msg})
    return True


def add_note_to_case(case_id, title, message, group_id=None, group_title=None):
    # Initiate a session with our API key and host. Session stays the same during all the script run.
    if group_id is None and group_title is None:
        group_title = "IRIS-SOAR Audit"

    session = ClientSession(
        apikey=config["api_key"],
        host=config["url"],
        ssl_verify=False,
    )

    # Get the Case from IRIS
    case = Case(session=session)

    # Fetch the case from its ID.
    if not case.case_id_exists(cid=case_id):
        mlog.error(f"Case ID {str(case_id)} not found !")
        return 0, False

    # Attribute the cid to the case instance
    case.set_cid(cid=case_id)
    if not group_id:
        response_group = case.add_notes_group(group_title, cid=case_id)
        if not response_group.is_success():
            mlog.error(f"Could not create group for case: {response_group.log_error()}")
            return 0, False
        group_id = response_group.get_data()["group_id"]

    response = case.add_note(title, message, group_id, cid=case_id)
    if not response.is_success():
        mlog.error(f"Could not add note to case: {case.log_error()}")
        return group_id, False
    return group_id, True


def get_alert_by_id(alert_id):
    # Initiate a session with our API key and host. Session stays the same during all the script run.
    session = ClientSession(
        apikey=config["api_key"],
        host=config["url"],
        ssl_verify=False,
    )

    # Get the alert
    alert = Alert(session=session)
    current_alert = alert.get_alert(alert_id)
    if not current_alert.is_success():
        mlog.error(f"Could not get alert from IRIS: {current_alert.log_error()}")
        return None
    else:
        mlog.debug(f"Got alert from IRIS: {current_alert.get_data()}")
        return current_alert.get_data()


# get_alert_by_id(4)
