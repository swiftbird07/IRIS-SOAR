# Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to get further context from the Elastic SIEM for all alerts.
#
# Acceptable Alerts:
#  - All Alerts
#
# Gathered Context:
# - ContextFlow, ContextProcess, ContextFile, ContextRegistry
#
# Actions:
# - Add notes to related iris-cases
#
PB_NAME = "PB_021_Advanced_Elastic_Context"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

TIME_DELTA_MINUTES_BEFORE = 3
TIME_DELTA_MINUTES_AFTER = 1

import datetime

from lib.class_helper import (
    CaseFile,
    AuditLog,
    Alert,
    ContextLog,
    ContextFlow,
    ContextFile,
    Rule,
    ContextProcess,
    ContextRegistry,
)
from lib.logging_helper import Log
from lib.config_helper import Config
from integrations.dfir-iris import irsoar_add_note_to_iris_case, irsoar_update_iris_case_title
from integrations.elastic_siem import irsoar_provide_context_for_alerts
from lib.generic_helper import format_results, dict_get
from case_playbooks.bb_elastic_context_fetcher import (
    bb_get_context_process_parents,
    bb_get_context_process_children,
    bb_get_context_process_file_events,
    bb_get_context_process_network_flows,
    bb_get_context_process_registry_events,
    bb_get_context_process_tree_visualisation,
)

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_stdout"]
mlog = Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


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

    for alert in case_file.alerts:
        # Check if any of the detecions of the alert case is a QRadar Offense
        try:
            case_file.get_iris_case_number()
        except ValueError:
            mlog.info(
                f"Playbook '{PB_NAME}' cannot handle alert '{alert.name}' ({alert.uuid}), as there is noiris-casein it."
            )
            return False

        if alert.vendor_id == "IBM QRadar":
            mlog.info(f"Playbook '{PB_NAME}' can handle alert '{alert.name}' ({alert.uuid}).")
            return True
        elif alert.vendor_id == "elastic_siem":
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
    for alert in case_file.alerts:
        alert: Alert
        if alert.vendor_id == "IBM QRadar" or alert.vendor_id == "elastic_siem":
            mlog.info("Handling QRadar Offense.")
            config = Config().cfg["integrations"]["elastic_siem"]

            if alert.flow:
                # First search for the process that is related to the alert
                current_action = AuditLog(
                    PB_NAME,
                    1,
                    "Searching for process related to alert by destination ip.",
                    "Searchin for process related to alert by the destination ip given in the alert.",
                )
                case_file.update_audit(current_action, logger=mlog)
                processes = irsoar_provide_context_for_alerts(
                    config, case_file, ContextProcess, False, alert.flow.destination_ip, search_type="dest_ip"
                )
                mlog.info(f"Found {len(processes)} processes related to alert {alert.uuid} destination ip.")
                alert.process = processes[0]

                if processes and len(processes) > 0:
                    case_file.update_audit(
                        current_action.set_successful(
                            message=f"Found {len(processes)} processes related to alert destination ip."
                        ),
                    )

                    for process in processes:
                        case_file.add_context(process)
                else:
                    case_file.update_audit(
                        current_action.set_warning(warning_message=f"Found no processes related to alert destination ip.")
                    )

            # Now search for all events of the alerted host at that time
            current_action = AuditLog(
                PB_NAME,
                2,
                "Searching all events of the alerted host at that time.",
                "Searching all events of the alerted host in a time range around the alert.",
            )
            case_file.update_audit(current_action, logger=mlog)

            if alert.device:
                host_ip = alert.device.local_ip
                start_time = alert.timestamp - datetime.timedelta(minutes=TIME_DELTA_MINUTES_BEFORE)
                end_time = alert.timestamp + datetime.timedelta(minutes=TIME_DELTA_MINUTES_AFTER)

                # Search for all events of the host at that time
                processes = irsoar_provide_context_for_alerts(
                    config,
                    case_file,
                    ContextProcess,
                    False,
                    host_ip,
                    search_start=start_time,
                    search_end=end_time,
                    search_type="host_ip",
                )

                if processes and len(processes) > 0:
                    mlog.info(
                        f"Found {len(processes)} processes related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                else:
                    mlog.info(
                        f"Found no processes related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"Found no processes related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                        ),
                        logger=mlog,
                    )

                flows = irsoar_provide_context_for_alerts(
                    config,
                    case_file,
                    ContextFlow,
                    False,
                    host_ip,
                    search_start=start_time,
                    search_end=end_time,
                    search_type="host_ip",
                )

                if flows and len(flows) > 0:
                    mlog.info(
                        f"Found {len(flows)} flows related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                else:
                    mlog.info(
                        f"Found no flows related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"Found no flows related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                        ),
                        logger=mlog,
                    )

                files = irsoar_provide_context_for_alerts(
                    config,
                    case_file,
                    ContextFile,
                    False,
                    host_ip,
                    search_start=start_time,
                    search_end=end_time,
                    search_type="host_ip",
                )

                if files and len(files) > 0:
                    mlog.info(
                        f"Found {len(files)} files related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                else:
                    mlog.info(
                        f"Found no files related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"Found no files related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                        ),
                        logger=mlog,
                    )

                registry = irsoar_provide_context_for_alerts(
                    config,
                    case_file,
                    ContextRegistry,
                    False,
                    host_ip,
                    search_start=start_time,
                    search_end=end_time,
                    search_type="host_ip",
                )

                if registry and len(registry) > 0:
                    mlog.info(
                        f"Found {len(registry)} registry events related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                else:
                    mlog.info(
                        f"Found no registry events related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                    )
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"Found no registry events related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                        ),
                        logger=mlog,
                    )

                if (
                    (processes and len(processes) > 0)
                    or (flows and len(flows) > 0)
                    or (files and len(files) > 0)
                    or (registry and len(registry) > 0)
                ):
                    if not processes:
                        processes = []
                    if not flows:
                        flows = []
                    if not files:
                        files = []
                    if not registry:
                        registry = []

                    case_file.update_audit(
                        current_action.set_successful(
                            message=f"Found {len(processes)} processes, {len(flows)} flows, {len(files)} files and {len(registry)} registry events related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                        ),
                        logger=mlog,
                    )
                else:
                    case_file.update_audit(
                        current_action.set_error(
                            message=f"Found no processes, flows, files or registry events related to host {host_ip} at time {alert.timestamp} (before {TIME_DELTA_MINUTES_BEFORE} minutes and after {TIME_DELTA_MINUTES_AFTER} minutes)."
                        ),
                        logger=mlog,
                    )

                # Add all contexts to the alert case:
                if processes:
                    for process in processes:
                        case_file.add_context(process)

                if flows:
                    for flow in flows:
                        case_file.add_context(flow)

                if files:
                    for file in files:
                        case_file.add_context(file)

                if registry:
                    for reg in registry:
                        case_file.add_context(reg)

    # Gather process related contexts from BB_Elastic_Context_Fetcher:
    current_action = AuditLog(
        PB_NAME,
        3,
        "Gather process related contexts from BB_Elastic_Context_Fetcher",
        "Gathering all process related contexts from the BB_Elastic_Context_Fetcher functions.",
    )
    case_file.update_audit(current_action, logger=mlog)
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

    if len(parents) > 0 or len(children) > 0:
        case_file.update_audit(
            current_action.set_successful(
                message=f"Found {len(parents)} parents and {len(children)} children for process {process_names} at time {alert.timestamp}."
            ),
            logger=mlog,
        )
    else:
        case_file.update_audit(
            current_action.set_warning(
                warning_message=f"Found no parents and no children for process {process_names} at time {alert.timestamp}."
            ),
            logger=mlog,
        )

    # Create a note for Process Context
    current_action = AuditLog(
        PB_NAME, 4, "Create a notes for all new contexts", "Creating a newiris-casenote for all new contexts."
    )
    case_file.update_audit(current_action, logger=mlog)
    iris_case_number = case_file.get_iris_case_number()

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
        gather_type="time range",
    )

    # Create a note for Network Flows
    irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_network",
        False,
        playbook_name=PB_NAME,
        playbook_step=8,
        case_file=case_file,
        alert=alert,
        alert_contexts=None,
        other_contexts=None,
        gather_type="time range",
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
        alert_contexts=None,
        other_contexts=None,
        file_names=None,
        gather_type="time range",
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
        alert_contexts=None,
        other_contexts=None,
        gather_type="time range",
    )

    case_file.update_audit(
        current_action.set_successful(message=f"Finished creating all notes for all new contexts."), logger=mlog
    )
