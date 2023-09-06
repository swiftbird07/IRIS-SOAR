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
