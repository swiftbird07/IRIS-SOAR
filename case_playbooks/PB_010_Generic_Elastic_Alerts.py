# Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally handle Elastic SIEM (formerly known as Elastic Endpoint Security) alert alerts.
#
# Acceptable Alerts:
#  - All elastic alerts
#
# Gathered Context:
# - ContextProcess, ContextFile, ContextRegistry, ContextNetwork
#
# Actions:
# - Create IRIS Case
# - Add notes to related iris-cases
#
PB_NAME = "PB_010_Generic_Elastic_Alerts"
PB_VERSION = "0.2.0"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True


from typing import Union, List
import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, AuditLog, Alert
from lib.config_helper import Config

from integrations.dfir-iris import irsoar_create_iris_case, irsoar_add_note_to_iris_case, irsoar_get_iris_case_by_number
from case_playbooks.bb_elastic_context_fetcher import (
    bb_get_context_process_children,
    bb_get_context_process_parents,
    bb_get_context_process_network_flows,
    bb_get_context_process_file_events,
    bb_get_context_process_registry_events,
    bb_get_context_process_tree_visualisation,
)

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["elastic_siem"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["elastic_siem"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def irsoar_can_handle_alert(case_file: CaseFile) -> bool:
    """Checks if this playbook can handle the alert.

    Args:
        case_file (CaseFile): The alert case

    Returns:
        bool: True if the playbook can handle the alert, False if not
    """
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling alert.")
        return False
    # Check if any of the detecions of the alert case is an Elastic Alert
    for alert in case_file.alerts:
        if alert.vendor_id == "elastic_siem":
            mlog.info(f"Playbook '{PB_NAME}' can handle alert '{alert.name}' ({alert.uuid}).")
            return True
    return False


def irsoar_handle_alert(case_file: CaseFile, DRY_RUN=False) -> CaseFile:
    """Handles the alert.

    Args:
        case_file (CaseFile): The alert case
        DRY_RUN (bool, optional): If True, no external changes will be made. Defaults to False.

    Returns:
        CaseFile: The alert case with the context processes
    """
    alert_title = case_file.get_title()
    alert_id = case_file.uuid
    current_action = AuditLog(
        PB_NAME,
        0,
        f"Checking Whitelist for alert '{alert_title}'",
        "Started handling alert case. Checking first if any alerts are whitelisted.",
    )
    case_file.update_audit(current_action, logger=mlog)

    alerts_to_handle = []
    for alert in case_file.alerts:
        if alert.vendor_id == "elastic_siem":
            mlog.debug(f"Adding alert: '{alert.name}' ({alert.uuid}) to list.")
            alerts_to_handle.append(alert)

    if len(alerts_to_handle) == 0:
        mlog.critical("Found no alerts in alert case to handle.")
        return case_file

    alert: Alert = alerts_to_handle[0]  #  We primarily handle the first alert

    # TODO: Handle indirect alert with event.outcome = unknown (e.g by signal.group.id: "b562097d6e9ffdde7981da7da11054cd23c61f5cfe2ba0583020f8b0ca463aef")

    # First check the global whitelist for whitelist entries
    mlog.info(f"Checking global whitelist for alert: '{alert.name}' ({alert.uuid})")
    if alert.check_against_whitelist():
        case_file.update_audit(current_action.set_successful(message="Alert is whitelisted, skipping."), logger=mlog)
        return case_file
    case_file.update_audit(current_action.set_successful(message="Alert is not whitelisted."), logger=mlog)

    # Create initialiris-casefor alert
    iris_case_number = irsoar_create_iris_case(
        case_file, alert, False, auto_alert_note=True, playbook_name=PB_NAME, playbook_step=1
    )
    if not iris_case_number:
        mlog.critical(f"Could not createiris-casefor alert: '{alert.name}' ({alert.uuid})")
        return case_file

    # Create additional notes for each other alert in the alert case
    if len(case_file.alerts) > 1:
        sub_step = 1
        for other_alert in case_file.alerts:
            if other_alert.uuid != alert.uuid:
                irsoar_add_note_to_iris_case(
                    iris_case_number,
                    case_file,
                    other_alert,
                    False,
                    auto_alert_note=True,
                    playbook_name=PB_NAME,
                    playbook_step=100 + sub_step,
                )
                sub_step += 1

    # Adding ticket to alert (-case)
    mlog.debug(f"Adding caseto alert and alert case.")
    if not DRY_RUN:
       iris_case = irsoar_get_iris_case_by_number(iris_case_number)
        alertiris_case = iris-case
        case_file.add_context(iris_case)

    # Gather process related contexts from BB_Elastic_Context_Fetcher:
    parents = []
    children = []
    process_tree = ""

    parents = bb_get_context_process_parents(PB_NAME, 2, mlog, case_file, alert)
    children = bb_get_context_process_children(PB_NAME, 3, mlog, case_file, alert)
    process_tree = bb_get_context_process_tree_visualisation(
        PB_NAME, 4, mlog, case_file, alert, parents, children, current_action
    )

    process_names = []
    for process in case_file.context_processes:
        process_names.append(f"{process.process_name} ({process.process_id})")

    # Create a note for Process Context
    irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_process",
        False,
        playbook_name=PB_NAME,
        playbook_step=5,
        case_file=case_file,
        alert=alert,
        alert_contexts=process_names,
        parents=parents,
        children=children,
        tree=process_tree,
    )

    # Gather Network related contexts from BB_Elastic_Context_Fetcher:
    detected_process_flows = []
    context_process_flows = []
    detected_process_flows, context_process_flows = bb_get_context_process_network_flows(PB_NAME, 6, mlog, case_file, alert)

    # Create a note for Network Flows
    irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_network",
        False,
        playbook_name=PB_NAME,
        playbook_step=8,
        case_file=case_file,
        alert=alert,
        alert_contexts=detected_process_flows,
        other_contexts=context_process_flows,
    )

    # Gather File related contexts from BB_Elastic_Context_Fetcher:
    detected_process_file_events = []
    context_processes_file_events = []
    detected_process_file_events, context_processes_file_events, file_names = bb_get_context_process_file_events(
        PB_NAME, 8, mlog, case_file, alert
    )

    # Create a note for File Events
    irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_file",
        False,
        playbook_name=PB_NAME,
        playbook_step=10,
        case_file=case_file,
        alert=alert,
        alert_contexts=detected_process_file_events,
        other_contexts=context_processes_file_events,
        file_names=file_names,
    )

    # Gather Registry related contexts from BB_Elastic_Context_Fetcher:
    detected_process_registry_events = []
    context_processes_registry_events = []
    detected_process_registry_events, context_processes_registry_events, _ = bb_get_context_process_registry_events(
        PB_NAME, 10, mlog, case_file, alert
    )

    # Create a note for Registry Events
    irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_registry",
        False,
        playbook_name=PB_NAME,
        playbook_step=12,
        case_file=case_file,
        alert=alert,
        alert_contexts=detected_process_registry_events,
        other_contexts=context_processes_registry_events,
    )

    return case_file


# TODO:
# - Cache new alert and check if it similar events already in the cache
# - Empty cache if too big
# - Worker: Kill Playbook if stuck
# - Audit log respecting timeline order
# - Audit log to IRIS Case
# - Log / Audit Log to Syslog
