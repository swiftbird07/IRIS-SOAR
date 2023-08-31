# Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally handle IBM QRadar Offenses and add context to them.
#
# Acceptable Detections:
#  - All elastic detections
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

from lib.class_helper import CaseFile, AuditLog, Detection, ContextLog, ContextFlow, ContextFile
from lib.logging_helper import Log
from lib.config_helper import Config
from integrations.dfir-iris import zs_create_iris_case, zs_add_note_to_iris_case, zs_get_iris_case_by_number
from integrations.ibm_qradar import zs_provide_context_for_detections

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["ibm_qradar"]["logging"]["log_level_stdout"]
mlog = Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def zs_can_handle_detection(case_file: CaseFile) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        case_file (CaseFile): The detection case

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling detection.")
        return False
    # Check if any of the detecions of the detection case is a QRadar Offense
    for detection in case_file.detections:
        if detection.vendor_id == "IBM QRadar":
            mlog.info(f"Playbook '{PB_NAME}' can handle detection '{detection.name}' ({detection.uuid}).")
            return True
    return False


def zs_handle_detection(case_file: CaseFile, DRY_RUN=False) -> CaseFile:
    """Handles the detection.

    Args:
        case_file (CaseFile): The detection case
        DRY_RUN (bool, optional): If True, no external changes will be made. Defaults to False.

    Returns:
        CaseFile: The detection case with the context processes
    """
    detection_title = case_file.get_title()
    detections_to_handle = []
    for detection in case_file.detections:
        if detection.vendor_id == "IBM QRadar":
            mlog.debug(f"Adding detection: '{detection.name}' ({detection.uuid}) to list.")
            detections_to_handle.append(detection)

    if len(detections_to_handle) == 0:
        mlog.critical("Found no detections in detection case to handle.")
        return case_file

    detection: Detection = detections_to_handle[0]  # We primarily handle the first detection

    # First check the global whitelist for whitelist entries
    current_action = AuditLog(
        PB_NAME,
        0,
        f"Checking Whitelist for detection '{detection_title}'",
        "Started handling detection case. Checking first if any detections are whitelisted.",
    )
    case_file.update_audit(current_action, logger=mlog)
    mlog.info(f"Checking global whitelist for detection: '{detection.name}' ({detection.uuid})")
    if detection.check_against_whitelist():
        case_file.update_audit(current_action.set_successful(message="Detection is whitelisted, skipping."), logger=mlog)
        return case_file
    case_file.update_audit(current_action.set_successful(message="Detection is not whitelisted."), logger=mlog)

    current_action = AuditLog(PB_NAME, 1, f"Creating iris-case", f"Creatingiris-casefor detection '{detection_title}'")
    # Create initialiris-casefor detection
    iris_case_number = zs_create_iris_case(
        case_file, detection, False, auto_detection_note=True, playbook_name=PB_NAME, playbook_step=1
    )
    if not iris_case_number:
        mlog.critical(f"Could not createiris-casefor detection: '{detection.name}' ({detection.uuid})")
        case_file.update_audit(current_action.set_error(message=f"Could not create iris_case."), logger=mlog)
        return case_file
    case_file.update_audit(current_action.set_successful(message=f"Creatediris-case'{iris_case_number}'."), logger=mlog)

    # Create additional notes for each other detection in the detection case
    if len(case_file.detections) > 1:
        sub_step = 1
        for other_detection in case_file.detections:
            if other_detection.uuid != detection.uuid:
                zs_add_note_to_iris_case(
                    iris_case_number,
                    case_file,
                    other_detection,
                    False,
                    auto_detection_note=True,
                    playbook_name=PB_NAME,
                    playbook_step=100 + sub_step,
                )
                sub_step += 1

    # Addiris-caseto detection (-case)
    mlog.debug(f"Addingiris-caseto detection and detection case.")
    if not DRY_RUN:
       iris-case= zs_get_iris_case_by_number(iris_case_number)
        detectioniris_case = iris-case
        case_file.add_context(iris_case)

    # Gather offense related context
    current_action = AuditLog(
        PB_NAME,
        3,
        f"Gathering further context for offense '{detection_title}'",
        "Started gathering context of events that were in the original offense.",
    )
    case_file.update_audit(current_action, logger=mlog)
    flows = []
    flows = zs_provide_context_for_detections(case_file, ContextFlow, search_type="offense", search_value=detection.uuid)
    if type(flows) is Exception:
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{detection_title}'. Error: {flows}", data=flows
            ),
            logger=mlog,
        )
        flows = []
    elif flows:
        for flow in flows:
            case_file.add_context(flow)

    logs = []
    logs = zs_provide_context_for_detections(case_file, ContextLog, search_type="offense", search_value=detection.uuid)
    if type(logs) is Exception:
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{detection_title}'. Error: {logs}", data=logs
            ),
            logger=mlog,
        )
        logs = []
    elif logs:
        for log in logs:
            case_file.add_context(log)

    files = []
    files = zs_provide_context_for_detections(case_file, ContextFile, search_type="offense", search_value=detection.uuid)
    if type(files) is Exception:
        case_file.update_audit(
            current_action.set_error(
                message=f"Could not gather context for offense '{detection_title}'. Error: {files}", data=files
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
    note_id_1 = zs_add_note_to_iris_case(
        iris_case_number,
        "context_network",
        False,
        playbook_name=PB_NAME,
        playbook_step=4,
        case_file=case_file,
        detection=detection,
        detection_contexts=flows,
    )
    note_id_2 = zs_add_note_to_iris_case(
        iris_case_number,
        "context_log",
        False,
        playbook_name=PB_NAME,
        playbook_step=5,
        case_file=case_file,
        detection=detection,
        detection_contexts=logs,
    )
    note_id_3 = zs_add_note_to_iris_case(
        iris_case_number,
        "context_file",
        False,
        playbook_name=PB_NAME,
        playbook_step=6,
        case_file=case_file,
        detection=detection,
        detection_contexts=files,
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

    # Addiris-caseto detection (-case)
    mlog.debug(f"Addingiris-caseto detection and detection case.")
   iris-case= zs_get_iris_case_by_number(iris_case_number)
    detectioniris_case = iris-case
    case_file.add_context(iris_case)

    return case_file
