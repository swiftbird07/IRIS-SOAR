# Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally handle IBM QRadar Offenses and add context to them.
#
# Acceptable Alerts:
#  - All elastic alerts
#
# Gathered Context:
# - ContextLog, ContextFlow, ContextFile
#
# Actions:
# - Create IRIS Case
# - Add notes to related iris-cases
#
PB_NAME = "PB_011_Generic_QRadar_Offenses"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

from lib.class_helper import CaseFile, AuditLog, Alert, ContextLog, ContextFlow, ContextFile
from lib.logging_helper import Log
from lib.config_helper import Config
from integrations.dfir-iris import irsoar_create_iris_case, irsoar_add_note_to_iris_case, irsoar_get_iris_case_by_number
from integrations.ibm_qradar import irsoar_provide_context_for_alerts

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
    # Check if any of the detecions of the alert case is a QRadar Offense
    for alert in case_file.alerts:
        if alert.vendor_id == "IBM QRadar":
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
    alerts_to_handle = []
    for alert in case_file.alerts:
        if alert.vendor_id == "IBM QRadar":
            mlog.debug(f"Adding alert: '{alert.name}' ({alert.uuid}) to list.")
            alerts_to_handle.append(alert)

    if len(alerts_to_handle) == 0:
        mlog.critical("Found no alerts in alert case to handle.")
        return case_file

    alert: Alert = alerts_to_handle[0]  # We primarily handle the first alert

    # First check the global whitelist for whitelist entries
    current_action = AuditLog(
        PB_NAME,
        0,
        f"Checking Whitelist for alert '{alert_title}'",
        "Started handling alert case. Checking first if any alerts are whitelisted.",
    )
    case_file.update_audit(current_action, logger=mlog)
    mlog.info(f"Checking global whitelist for alert: '{alert.name}' ({alert.uuid})")
    if alert.check_against_whitelist():
        case_file.update_audit(current_action.set_successful(message="Alert is whitelisted, skipping."), logger=mlog)
        return case_file
    case_file.update_audit(current_action.set_successful(message="Alert is not whitelisted."), logger=mlog)

    current_action = AuditLog(PB_NAME, 1, f"Creating iris-case", f"Creatingiris-casefor alert '{alert_title}'")
    # Create initialiris-casefor alert
    iris_case_number = irsoar_create_iris_case(
        case_file, alert, False, auto_alert_note=True, playbook_name=PB_NAME, playbook_step=1
    )
    if not iris_case_number:
        mlog.critical(f"Could not createiris-casefor alert: '{alert.name}' ({alert.uuid})")
        case_file.update_audit(current_action.set_error(message=f"Could not create iris_case."), logger=mlog)
        return case_file
    case_file.update_audit(current_action.set_successful(message=f"Creatediris-case'{iris_case_number}'."), logger=mlog)

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

    # Addiris-caseto alert (-case)
    mlog.debug(f"Adding caseto alert and alert case.")
    if not DRY_RUN:
       iris-case= irsoar_get_iris_case_by_number(iris_case_number)
        alertiris_case = iris-case
        case_file.add_context(iris_case)

    # Gather offense related context
    current_action = AuditLog(
        PB_NAME,
        3,
        f"Gathering further context for offense '{alert_title}'",
        "Started gathering context of events that were in the original offense.",
    )
    case_file.update_audit(current_action, logger=mlog)
    flows = []
    flows = irsoar_provide_context_for_alerts(case_file, ContextFlow, search_type="offense", search_value=alert.uuid)
    if type(flows) is Exception:
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{alert_title}'. Error: {flows}", data=flows
            ),
            logger=mlog,
        )
        flows = []
    elif flows:
        for flow in flows:
            case_file.add_context(flow)

    logs = []
    logs = irsoar_provide_context_for_alerts(case_file, ContextLog, search_type="offense", search_value=alert.uuid)
    if type(logs) is Exception:
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{alert_title}'. Error: {logs}", data=logs
            ),
            logger=mlog,
        )
        logs = []
    elif logs:
        for log in logs:
            case_file.add_context(log)

    files = []
    files = irsoar_provide_context_for_alerts(case_file, ContextFile, search_type="offense", search_value=alert.uuid)
    if type(files) is Exception:
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{alert_title}'. Error: {files}", data=files
            ),
            logger=mlog,
        )
        files = []
    elif files:
        for file in files:
            case_file.add_context(file)

    if len(flows) > 0 or len(logs) > 0 or len(files) > 0:
        case_file.update_audit(
            current_action.set_successful(
                message=f"Found {len(flows)} flows, {len(logs)} logs and {len(files)} files that were in the original offense."
            ),
            logger=mlog,
        )
    else:
        case_file.update_audit(
            current_action.set_warning(warning_message=f"Found no flows, logs or files that were in the original offense."),
            logger=mlog,
        )

    current_action = AuditLog(
        PB_NAME, 4, f"Adding context toiris-case'{iris_case_number}'", "Started adding context to iris_case."
    )

    # Create a note for each context
    note_id_1 = irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_network",
        False,
        playbook_name=PB_NAME,
        playbook_step=4,
        case_file=case_file,
        alert=alert,
        alert_contexts=flows,
    )
    note_id_2 = irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_log",
        False,
        playbook_name=PB_NAME,
        playbook_step=5,
        case_file=case_file,
        alert=alert,
        alert_contexts=logs,
    )
    note_id_3 = irsoar_add_note_to_iris_case(
        iris_case_number,
        "context_file",
        False,
        playbook_name=PB_NAME,
        playbook_step=6,
        case_file=case_file,
        alert=alert,
        alert_contexts=files,
    )

    if not note_id_1 or type(note_id_1) is Exception:
        case_file.update_audit(
            current_action.set_error(message=f"Could not add context network toiris-case'{iris_case_number}'. Error: {note_id_1}"),
            logger=mlog,
        )

    if not note_id_2 or type(note_id_2) is Exception:
        case_file.update_audit(
            current_action.set_error(message=f"Could not add context log toiris-case'{iris_case_number}'. Error: {note_id_2}"),
            logger=mlog,
        )

    if not note_id_3 or type(note_id_3) is Exception:
        case_file.update_audit(
            current_action.set_error(message=f"Could not add context file toiris-case'{iris_case_number}'. Error: {note_id_3}"),
            logger=mlog,
        )

    if (
        note_id_1
        and note_id_2
        and note_id_3
        and type(note_id_1) is not Exception
        and type(note_id_2) is not Exception
        and type(note_id_3) is not Exception
    ):
        case_file.update_audit(
            current_action.set_successful(message=f"Successfully added all offense contexts toiris-case'{iris_case_number}'."),
            logger=mlog,
        )

    # Addiris-caseto alert (-case)
    mlog.debug(f"Adding caseto alert and alert case.")
   iris-case= irsoar_get_iris_case_by_number(iris_case_number)
    alertiris_case = iris-case
    case_file.add_context(iris_case)

    return case_file
