# Building Block for Z-SOAR Playbooks
# Created by: Martin Offermann
#
# This is a building block used by Z-SOAR Playbooks
# It is used to provide all available Elastic SIEM contexts for a given detection
# This building block is itself dependent on the building block "BB_Elastic_Process_Context".
#
# Acceptable Detections:
#  - Any
#
# Gathered Context:
# - ContextProcess, ContextFlow, ContextFile, ContextRegistry
#
# Actions:
# - None
#
BB_NAME = "BB_Elastic_Context_Fetcher"
BB_VERSION = "0.1.0"
BB_AUTHOR = "Martin Offermann"
BB_LICENSE = "MIT"
BB_ENABLED = True

import traceback

from lib.class_helper import Detection, CaseFile, Rule, ContextProcess, ContextLog, ContextFlow, ContextFile, AuditLog
from playbooks.bb_elastic_process_context import (
    bb_get_all_parents,
    bb_get_all_children,
    bb_make_process_tree_visualisation,
    bb_get_process_network_flows,
    bb_get_process_file_events,
    bb_get_process_registry_events,
)


def bb_get_context_process_parents(playbook_name, playbook_step, mlog, case_file: CaseFile, detection: Detection):
    """Get the parents of a process.

    Arguments:
        PB_NAME {str} -- The name of the playbook.
        mlog {Logger} -- The playbook's logger.
        case_file {CaseFile} -- The detection case.
        detection {Detection} -- The detection.

    Returns:
        list -- A list of ContextProcess objects.
    """
    current_sub_action = AuditLog(
        playbook_name, playbook_step, "Context - Get Parents", "Gathering Parent Process Context from Elastic."
    )
    case_file.update_audit(current_sub_action, logger=mlog)
    parents = []
    try:
        parents = bb_get_all_parents(case_file, detection.process)  #
    except Exception as e:
        mlog.error(
            f"Failed to get parents for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_sub_action.set_error(message=f"Failed to get parents for detection.", exception=e), logger=mlog
        )

    if parents is None:
        mlog.warning(f"Got no parents for detection.")
        case_file.update_audit(current_sub_action.set_warning(warning_message=f"Found no parents for detection."), logger=mlog)
    else:
        process_names = []
        for process in parents:
            process_names.append(f"{process.process_name} ({process.process_id})")
        case_file.update_audit(
            current_sub_action.set_successful(message=f"Found {len(parents)} parents for detection.", data=process_names),
            logger=mlog,
        )
    return parents


def bb_get_context_process_children(playbook_name, playbook_step, mlog, case_file: CaseFile, detection: Detection):
    """Get the children of a process.

    Arguments:
        PB_NAME {str} -- The name of the playbook.
        mlog {Logger} -- The playbook's logger.
        case_file {CaseFile} -- The detection case.
        detection {Detection} -- The detection.

    Returns:
        list -- A list of ContextProcess objects.
    """
    children = []
    thrown_count = 0
    current_sub_action = AuditLog(
        playbook_name, playbook_step, "Context - Get Children", "Gathering Children Process Context from Elastic."
    )
    try:
        children, thrown_count = bb_get_all_children(case_file, detection.process)
    except Exception as e:
        mlog.error(
            f"Failed to get children for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_sub_action.set_error(message=f"Failed to get children for detection.", exception=e), logger=mlog
        )

    if children is None:
        mlog.warning(f"Got no children for detection.")
        case_file.update_audit(current_sub_action.set_warning(warning_message=f"Found no children for detection."), logger=mlog)
    else:
        if thrown_count > 0:
            mlog.warning(
                f"[OVERFLOW PROTECTION] Got {len(children)} children for detection, but {thrown_count} children were thrown due to overflow protection."
            )
            case_file.update_audit(
                current_sub_action.set_warning(
                    warning_message=f"[OVERFLOW PROTECTION] Found {len(children)} children for detection, but {thrown_count} children were thrown due to overflow protection."
                ),
                logger=mlog,
            )

        process_names = []
        for process in children:
            process_names.append(f"{process.process_name}")
        case_file.update_audit(
            current_sub_action.set_successful(message=f"Found {len(children)} children for detection.", data=process_names),
            logger=mlog,
        )
    return children


def bb_get_context_process_tree_visualisation(
    playbook_name,
    playbook_step,
    mlog,
    case_file: CaseFile,
    detection: Detection,
    parents: list,
    children: list,
    current_action: AuditLog,
):
    """Create a process tree visualisation.

    Arguments:
        PB_NAME {str} -- The name of the playbook.
        mlog {Logger} -- The playbook's logger.
        case_file {CaseFile} -- The detection case.
        detection {Detection} -- The detection.
        parents {list} -- A list of ContextProcess objects.
        children {list} -- A list of ContextProcess objects.
        current_action {AuditLog} -- The current action AuditLog object.

    Returns:
        str -- The process tree visualisation.
    """
    process_tree = None
    if len(parents) > 0 or len(children) > 0:
        current_sub_action = AuditLog(playbook_name, playbook_step, "Context - Process Tree", "Gathering Process Tree from BB.")
        try:
            process_tree = bb_make_process_tree_visualisation(detection.process, parents, children)
        except Exception as e:
            mlog.error(
                f"Failed to create process tree visualisation for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
            )
            case_file.update_audit(
                current_sub_action.set_error(message=f"Failed to create process tree visualisation for detection.", exception=e),
                logger=mlog,
            )
        if process_tree == "":
            mlog.warning(f"Failed to get process tree visualisation for detection.")
            case_file.update_audit(
                current_sub_action.set_warning(
                    warning_message=f"Failed to get process tree visualisation for detection (empty response)."
                ),
                logger=mlog,
            )
        else:
            case_file.update_audit(
                current_sub_action.set_successful(
                    message=f"Successfully created process tree visualisation for detection.", data=process_tree
                ),
                logger=mlog,
            )
    else:
        case_file.update_audit(
            current_action.set_warning(warning_message=f"Found no context processes for detection."), logger=mlog
        )
    return process_tree


def bb_get_context_process_network_flows(playbook_name, playbook_step, mlog, case_file: CaseFile, detection: Detection):
    """Get the network flows of a process.

    Arguments:
        PB_NAME {str} -- The name of the playbook.
        mlog {Logger} -- The playbook's logger.
        case_file {CaseFile} -- The detection case.
        detection {Detection} -- The detection.

    Returns:
        list -- A list of ContextFlow objects related to the detected process.
        list -- A list of other ContextFlow objects
    """
    detected_process_flows = []

    # Gather network flows from alerted process
    try:
        current_action = AuditLog(
            playbook_name,
            playbook_step,
            "Context - Network Flows (Detected Process)",
            "Gathering network flows of detected process from BB.",
        )
        case_file.update_audit(current_action, logger=mlog)

        if detection.process:
            detected_process_flows, thrown_count = bb_get_process_network_flows(case_file, detection.process)

        if detection.flow:
            detected_process_flows.append(detection.flow)

        if len(detected_process_flows) == 0:
            mlog.warning(f"Got no network flows for detection.")
            case_file.update_audit(
                current_action.set_warning(warning_message=f"Found no network flows for detected process."), logger=mlog
            )
        else:
            destination_ips = []
            for flow in case_file.context_flows:  # Add all destination IPs from context flows to list for the audit log
                destination_ips.append(flow.destination_ip)

            case_file.update_audit(
                current_action.set_successful(
                    message=f"Found {len(detected_process_flows)} network flows for detected process.", data=destination_ips
                ),
                logger=mlog,
            )

            if thrown_count > 0:
                mlog.warning(f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows for detected process.")
                case_file.update_audit(
                    current_action.set_warning(
                        warning_message=f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows out for detected process, due to overflow protection."
                    ),
                    logger=mlog,
                )

    except Exception as e:
        mlog.error(
            f"Failed to get network flows for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_action.set_error(message=f"Failed to get network flows for detection.", exception=traceback.format_exc()),
            logger=mlog,
        )

    # Gather network flows from (other) context processes
    try:
        current_action = AuditLog(
            playbook_name,
            playbook_step + 1,
            "Context - Network Flows (Other Processes)",
            "Gathering network flows of other processes from BB.",
        )
        case_file.update_audit(current_action, logger=mlog)
        context_process_flows = []
        thrown_count = 0

        for process in case_file.context_processes:
            new_flow, thrown_count = bb_get_process_network_flows(case_file, process)
            if new_flow is not None:
                if thrown_count > 0:
                    mlog.warning(
                        f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows out for process: {process.process_name} ({process.process_id})."
                    )
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"[OVERFLOW PROTECTION] Threw {thrown_count} network flows out for process: {process.process_name} ({process.process_id}), due to overflow protection."
                        ),
                        logger=mlog,
                    )

                context_process_flows += new_flow
        if len(context_process_flows) == 0:
            mlog.warning(f"Got no network flows from other processes.")
            case_file.update_audit(
                current_action.set_warning(warning_message=f"Found no network flows for other context processes."), logger=mlog
            )
        else:
            destination_ips = []
            for flow in case_file.context_flows:  # Add all destination IPs from context flows to list for the audit log
                destination_ips.append(flow.destination_ip)

            case_file.update_audit(
                current_action.set_successful(
                    message=f"Found {len(context_process_flows)} network flows for other processes of detection.",
                    data=destination_ips,
                ),
                logger=mlog,
            )
    except Exception as e:
        mlog.error(
            f"Failed to get network flows for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_action.set_error(message=f"Failed to get network flows for detection.", exception=traceback.format_exc()),
            logger=mlog,
        )

    case_file.update_audit(
        current_action.set_successful(message=f"Successfully gathered needed context for detection."), logger=mlog
    )
    return detected_process_flows, context_process_flows


def bb_get_context_process_file_events(playbook_name, playbook_step, mlog, case_file: CaseFile, detection: Detection):
    """Get the file events of a process.

    Arguments:
        PB_NAME {str} -- The name of the playbook.
        mlog {Logger} -- The playbook's logger.
        case_file {CaseFile} -- The detection case.
        detection {Detection} -- The detection.

    Returns:
        list -- A list of ContextFlow objects related to the detected process.
        list -- A list of other ContextFlow objects
        list -- A list of file names
    """
    # Gather file events from alerted process
    detected_process_file_events = []
    file_names = []
    try:
        current_action = AuditLog(
            playbook_name, playbook_step, "File Events - Alerted Process", "Gathering file events of alerted process from BB."
        )
        case_file.update_audit(current_action, logger=mlog)
        if detection.process:
            detected_process_file_events, thrown = bb_get_process_file_events(case_file, detection.process)

        if detection.file:
            detected_process_file_events.append(detection.file)

        if len(detected_process_file_events) == 0:
            mlog.warning(f"Got no file events for detection.")
            case_file.update_audit(
                current_action.set_warning(warning_message=f"Found no file events for detected process."), logger=mlog
            )
        else:
            file_names = []
            for event in detected_process_file_events:  # Gather all file names for the audit log
                file_names.append(event.file_name)
            case_file.update_audit(
                current_action.set_successful(
                    message=f"Found {len(detected_process_file_events)} file events for detected process.", data=file_names
                ),
                logger=mlog,
            )
    except Exception as e:
        mlog.error(
            f"Failed to get file events for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_action.set_error(message=f"Failed to get file events for detection.", exception=e), logger=mlog
        )

    # Gather file events from other context processes
    try:
        current_action = AuditLog(
            playbook_name, playbook_step + 1, "File Events - Other Processes", "Gathering file events of other processes from BB."
        )
        case_file.update_audit(current_action, logger=mlog)
        context_processes_file_events = []
        thrown_count = 0

        for process in case_file.context_processes:
            new_events, thrown_count = bb_get_process_file_events(case_file, process)
            if new_events is not None:
                if thrown_count > 0:
                    mlog.warning(
                        f"[OVERFLOW PROTECTION] Threw {thrown_count} file events out for process: {process.process_name} ({process.process_id})."
                    )
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"[OVERFLOW PROTECTION] Threw {thrown_count} file events out for process: {process.process_name} ({process.process_id}), due to overflow protection."
                        ),
                        logger=mlog,
                    )

                context_processes_file_events += new_events
        if len(context_processes_file_events) == 0:
            mlog.warning(f"Got no file events from other processes.")
            case_file.update_audit(
                current_action.set_warning(warning_message=f"Found no file events for other context processes."), logger=mlog
            )
        else:
            file_names = []
            for event in context_processes_file_events:  # Gather all file names for the audit log
                file_names.append(event.file_name)
            case_file.update_audit(
                current_action.set_successful(
                    message=f"Found {len(context_processes_file_events)} file events for other processes of detection.",
                    data=file_names,
                ),
                logger=mlog,
            )
    except Exception as e:
        mlog.error(
            f"Failed to get file events for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_action.set_error(message=f"Failed to get file events for detection.", exception=e), logger=mlog
        )
    return detected_process_file_events, context_processes_file_events, file_names


def bb_get_context_process_registry_events(playbook_name, playbook_step, mlog, case_file: CaseFile, detection: Detection):
    """Get the registry events of a process.

    Arguments:
        PB_NAME {str} -- The name of the playbook.
        mlog {Logger} -- The playbook's logger.
        case_file {CaseFile} -- The detection case.
        detection {Detection} -- The detection.

    Returns:
        list -- A list of ContextFlow objects related to the detected process.
        list -- A list of other ContextFlow objects
        list -- A list of registry keys
    """
    # Gatther registry events from detected process
    detected_process_registry_events = []
    try:
        current_action = AuditLog(
            playbook_name,
            playbook_step,
            "Registry Events - Detected Process",
            "Gathering registry events of detected process from BB.",
        )
        case_file.update_audit(current_action, logger=mlog)
        if detection.process:
            detected_process_registry_events, thrown = bb_get_process_registry_events(case_file, detection.process)

        if detection.registry:
            detected_process_registry_events.append(detection.registry)

        if len(detected_process_registry_events) == 0:
            mlog.warning(f"Got no registry events from detected process.")
            case_file.update_audit(
                current_action.set_warning(warning_message=f"Found no registry events for detected process."), logger=mlog
            )
        else:
            registry_keys = []
            for event in detected_process_registry_events:  # Gather all registry keys for the audit log
                registry_keys.append(event.registry_key)
            case_file.update_audit(
                current_action.set_successful(
                    message=f"Found {len(detected_process_registry_events)} registry events for detected process.",
                    data=registry_keys,
                ),
                logger=mlog,
            )

    except Exception as e:
        mlog.error(
            f"Failed to get registry events for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_action.set_error(message=f"Failed to get registry events for detection.", exception=e), logger=mlog
        )

    # Gatther registry events from other processes
    registry_keys = []
    try:
        current_action = AuditLog(
            playbook_name,
            playbook_step + 1,
            "Registry Events - Other Processes",
            "Gathering registry events of other processes from BB.",
        )
        case_file.update_audit(current_action, logger=mlog)
        context_processes_registry_events = []
        thrown_count = 0
        for process in case_file.context_processes:
            new_events, thrown = bb_get_process_registry_events(case_file, process)
            if new_events is not None:
                context_processes_registry_events += new_events
        if len(context_processes_registry_events) == 0:
            mlog.warning(f"Got no registry events from other processes.")
            case_file.update_audit(
                current_action.set_warning(warning_message=f"Found no registry events for other context processes."), logger=mlog
            )
        else:
            for event in context_processes_registry_events:  # Gather all registry keys for the audit log
                registry_keys.append(event.registry_key)
            case_file.update_audit(
                current_action.set_successful(
                    message=f"Found {len(context_processes_registry_events)} registry events for other processes of detection.",
                    data=registry_keys,
                ),
                logger=mlog,
            )

    except Exception as e:
        mlog.error(
            f"Failed to get registry events for detection: '{detection.name}' ({detection.uuid}). Exception: {traceback.format_exc()}"
        )
        case_file.update_audit(
            current_action.set_error(message=f"Failed to get registry events for detection.", exception=e), logger=mlog
        )
    return detected_process_registry_events, context_processes_registry_events, registry_keys
