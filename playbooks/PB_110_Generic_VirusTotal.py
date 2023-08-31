# Playbook for IRIS-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by IRIS-SOAR
# It is used to generally handle detections to add VirusTotal context to them.
# It is possible to differentiate between EDR and SIEM detections to extend the search for all context indicators for either case.
#
# Acceptable Detections:
#  - All detections that have any kind of indicator that is searchable in VirusTotal
#
# Gathered Context:
# - VirusTotal context for the provided indicators
#
# Actions:
# - Add notes to related iris-cases
#
PB_NAME = "PB_010_Generic_VirusTotal"
PB_VERSION = "0.1.0"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True

EDR_DETECTION_VENDORS = ["elastic_siem"]  # The vendors that are considered EDR detections.
SIEM_DETECTION_VENDORS = ["IBM QRadar"]  # The vendors that are considered SIEM detections.

EDR_SEARCH_CASE_FILE = True  # If True, the playbook will search for all indicators if any of the detections is an EDR detection
SIEM_SEARCH_CASE_FILE = True  # If True, the playbook will search for all indicators if any of the detections is a SIEM detection

WAIT_FOR_HASHES = False  # If True, the playbook will wait for the file/process hashes to be analyzed even if the API limit is reached. Not recommended on the free API, when many hashes are excpected (e.g. when using Elastic Integration)
WAIT_FOR_NETWORK = (
    True  # If True, the playbook will wait for the network connections to be analyzed even if the API limit is reached.
)

import ipaddress
from typing import Union, List

import lib.logging_helper as logging_helper
from lib.class_helper import CaseFile, ContextProcess, AuditLog, Detection, ContextThreatIntel, DNSQuery, HTTP
from lib.config_helper import Config
from lib.generic_helper import cast_to_ipaddress, format_results, is_local_tld

from integrations.virus_total import zs_provide_context_for_detections
from integrations.dfir-iris import zs_add_note_to_iris_case, zs_get_iris_case_by_number

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["virus_total"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["virus_total"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)


def zs_can_handle_detection(case_file: CaseFile) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        case_file (CaseFile): The detection case

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    # Check if any of the detecions of the detection case is an Elastic Alert
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling anything.")
        return False

    # Check if there is already airis-casefor the detection case
    try:
        iris_case_number = case_file.get_iris_case_number()
    except ValueError:
        mlog.info(f"Playbook '{PB_NAME}' cannot handle detection case '{case_file.uuid}' as there is noiris-casefor it.")
        return False

    # Check if any of the detecions of the detection case has an indicator that is searchable in VirusTotal
    for detection in case_file.detections:
        if (
            len(detection.indicators["ip"]) > 0
            or len(detection.indicators["domain"]) > 0
            or len(detection.indicators["url"]) > 0
            or len(detection.indicators["hash"]) > 0
        ):
            mlog.info(f"Playbook '{PB_NAME}' can handle detection '{detection.name}' ({detection.uuid}).")
            return True
    return False


def zs_handle_detection(case_file: CaseFile, TEST=False) -> CaseFile:
    """Handles the detection.

    Args:
        case_file (CaseFile): The detection case
        TEST (bool): True if the playbook is run in test mode, False if not

    Returns:
        CaseFile: The updated detection case
    """
    # Get all the indicators
    cfg = Config().cfg
    integration_config = cfg["integrations"]["virus_total"]
    mlog.info(f"Handling detection case '{case_file.uuid}'")
    init_action = AuditLog(PB_NAME, 0, "Handling detection case", "Started handling detection case by getting indicators")
    case_file.update_audit(init_action, mlog)

    indicators: List[str] = []
    network_contexts: List[ContextThreatIntel] = []
    process_contexts: List[ContextThreatIntel] = []

    try:
        iris_case_number = case_file.get_iris_case_number()
    except (
        ValueError
    ):  # Sanity check. Should not be raised, as zs_can_handle_detection() should have been called before to check if the detection case has airis-casenumber
        mlog.critical(
            f"Could not getiris-casenumber from detection case. Airis-casefor the detection case must be created by a previous playbook for this playbook to work."
        )
        case_file.update_audit(
            init_action.set_error(
                message="Could not getiris-casenumber from detection case. Airis-casefor the detection case must be created by a previous playbook for this playbook to work."
            ),
            mlog,
        )
        return case_file

    #                                                                      #
    ## STEP 1 - Get the threat intel for the indicators of all detections ##
    #                                                                      #

    ips = []
    domains = []
    urls = []
    hashes = []

    if case_file.detections[0].vendor_id in EDR_DETECTION_VENDORS and EDR_SEARCH_CASE_FILE:
        mlog.info(f"Searching for all indicators of detection case '{case_file.uuid}' as it is an EDR detection.")
        ips = case_file.indicators["ip"]
        domains = case_file.indicators["domain"]
        urls = case_file.indicators["url"]
        hashes = case_file.indicators["hash"]

    if case_file.detections[0].vendor_id in SIEM_DETECTION_VENDORS and SIEM_SEARCH_CASE_FILE:
        mlog.info(f"Searching for all indicators of detection case '{case_file.uuid}' as it is a SIEM detection.")
        ips = case_file.indicators["ip"]
        domains = case_file.indicators["domain"]
        urls = case_file.indicators["url"]
        hashes = case_file.indicators["hash"]

    for detection in case_file.detections:
        mlog.info(f"Handling detection '{detection.name}' ({detection.uuid})")

        # Get the indicators
        mlog.debug(f"Found indicators of detection: {detection.indicators}")
        detection: Detection = detection

        for indicator_type in detection.indicators:
            for indicator in detection.indicators[indicator_type]:
                if indicator_type == "ip":
                    ips.append(indicator)
                elif indicator_type == "domain":
                    domains.append(indicator)
                elif indicator_type == "url":
                    urls.append(indicator)
                elif indicator_type == "hash":
                    hashes.append(indicator)

        # Remove duplicates of the lists:
        ips = list(set(ips))
        domains = list(set(domains))
        urls = list(set(urls))
        hashes = list(set(hashes))

        if len(ips) > 0 or len(domains) > 0 or len(urls) > 0 or len(hashes) > 0:
            case_file.update_audit(init_action.set_successful("Got indicators", data=detection.indicators), mlog)
        else:
            case_file.update_audit(
                init_action.set_warning(warning_message=f"No indicators were found for detection {detection.name}."), mlog
            )
            continue

        if len(ips) > 0:
            mlog.debug(f"Found IPs: {ips}. Handling them.")
            current_action = AuditLog(PB_NAME, 1, "Handling IPs", "Started handling IPs")
            case_file.update_audit(current_action, mlog)
            for ip in ips:
                ip = cast_to_ipaddress(ip)

                if ip.is_private:
                    mlog.debug(f"IP '{ip}' is private. Skipping it.")
                    continue

                try:
                    nw_new = zs_provide_context_for_detections(
                        integration_config,
                        case_file,
                        required_type=ContextThreatIntel,
                        TEST=TEST,
                        search_type=type(ip),
                        search_value=ip,
                        maxContext=1,
                        wait_if_api_quota_exceeded=WAIT_FOR_NETWORK,
                    )
                    if nw_new:
                        network_contexts.append(nw_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for IP '{ip}': {e}")
                    case_file.update_audit(
                        current_action.set_error(message=f"Error while getting context for IP '{ip}': {e}", data=e), mlog
                    )

            if len(network_contexts) != 0:
                case_file.update_audit(
                    current_action.set_successful(
                        message=f"Got threat intel for {str(len(network_contexts))} out of {str(len(ips))} IPs", data=ips
                    ),
                    mlog,
                )
            else:
                # Check if all IPs were private
                had_public_ips = False
                for ip in ips:
                    ip = cast_to_ipaddress(ip)
                    if ip.is_global:
                        had_public_ips = True
                        break
                if had_public_ips:
                    case_file.update_audit(
                        current_action.set_warning(
                            warning_message=f"Could not get threat intel for any of the {str(len(ips))} IPs", data=ips
                        ),
                        mlog,
                    )
                else:
                    case_file.update_audit(
                        current_action.set_successful(
                            message=f"All {str(len(ips))} IPs were private. No threat intel search possible for them.", data=ips
                        ),
                        mlog,
                    )

        if len(domains) > 0:
            mlog.debug(f"Found domains: {domains}. Handling them.")
            current_action = AuditLog(PB_NAME, 2, "Handling domains", "Started handling domains")
            case_file.update_audit(current_action, mlog)
            for domain in domains:
                try:
                    if is_local_tld(domain):
                        mlog.debug(f"Domain '{domain}' is a local domain. Skipping it.")
                        continue
                    domain_new = zs_provide_context_for_detections(
                        integration_config,
                        case_file,
                        required_type=ContextThreatIntel,
                        TEST=TEST,
                        search_type=DNSQuery,
                        search_value=domain,
                        maxContext=1,
                        wait_if_api_quota_exceeded=WAIT_FOR_NETWORK,
                    )
                    if domain_new:
                        network_contexts.append(domain_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for domain '{domain}': {e}")
                    case_file.update_audit(
                        current_action.set_error(
                            warning_message=f"Error while getting context for domain '{domain}': {e}", data=e
                        ),
                        mlog,
                    )

            if len(network_contexts) != 0:
                case_file.update_audit(
                    current_action.set_successful(
                        message=f"Got threat intel for {str(len(network_contexts))} out of {str(len(domains))} domains",
                        data=domains,
                    ),
                    mlog,
                )
            else:
                case_file.update_audit(
                    current_action.set_warning(
                        warning_message=f"Could not get threat intel for any of the {str(len(domains))} domains", data=domains
                    ),
                    mlog,
                )

        if len(urls) > 0:
            mlog.debug(f"Found URLs: {urls}. Handling them.")
            current_action = AuditLog(PB_NAME, 3, "Handling URLs", "Started handling URLs")
            case_file.update_audit(current_action, mlog)
            for url in urls:
                try:
                    if is_local_tld(url.split("/")[2]):
                        mlog.debug(f"URL '{url}' is a local domain. Skipping it.")
                        continue
                    url_new = zs_provide_context_for_detections(
                        integration_config,
                        case_file,
                        required_type=ContextThreatIntel,
                        TEST=TEST,
                        search_type=HTTP,
                        search_value=url,
                        maxContext=1,
                        wait_if_api_quota_exceeded=WAIT_FOR_NETWORK,
                    )
                    if url_new:
                        network_contexts.append(url_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for URL '{url}': {e}")
                    case_file.update_audit(
                        current_action.set_error(message=f"Error while getting context for URL '{url}': {e}", data=e),
                        mlog,
                    )

            if len(network_contexts) != 0:
                case_file.update_audit(
                    current_action.set_successful(
                        message=f"Got threat intel for {str(len(network_contexts))} out of {str(len(urls))} URLs", data=urls
                    ),
                    mlog,
                )
            else:
                case_file.update_audit(
                    current_action.set_warning(
                        warning_message=f"Could not get threat intel for any of the {str(len(urls))} URLs", data=urls
                    ),
                    mlog,
                )

        if len(hashes) > 0:
            mlog.debug(f"Found hashes: {hashes}. Handling them.")
            current_action = AuditLog(PB_NAME, 4, "Handling hashes", "Started handling hashes")
            case_file.update_audit(current_action, mlog)
            for hash in hashes:
                try:
                    pc_new = zs_provide_context_for_detections(
                        integration_config,
                        case_file,
                        required_type=ContextThreatIntel,
                        TEST=TEST,
                        search_type=ContextProcess,
                        search_value=hash,
                        maxContext=1,
                        wait_if_api_quota_exceeded=WAIT_FOR_HASHES,
                    )
                    if pc_new:
                        process_contexts.append(pc_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for hash '{hash}': {e}")
                    case_file.update_audit(
                        current_action.set_error(message=f"Error while getting context for hash '{hash}': {e}", data=e),
                        mlog,
                    )

            if len(process_contexts) != 0:
                case_file.update_audit(
                    current_action.set_successful(
                        message=f"Got threat intel for {str(len(process_contexts))} out of {str(len(hashes))} hashes", data=hashes
                    ),
                    mlog,
                )
            else:
                case_file.update_audit(
                    current_action.set_warning(
                        warning_message=f"Could not get threat intel for any of the {str(len(hashes))} hashes", data=hashes
                    ),
                    mlog,
                )

        if len(ips) == 0 and len(domains) == 0 and len(urls) == 0 and len(hashes) == 0:
            mlog.info("No indicators found in this detection.")
        elif len(network_contexts) == 0 and len(process_contexts) == 0:
            mlog.info("Found indicators, but no threat intel for this detection.")
        else:
            mlog.info(
                f"Found {str(len(network_contexts))} network indicators and {str(len(process_contexts))} process indicators for this detection."
            )

    if not init_action.result_was_successful:
        case_file.update_audit(
            init_action.set_warning(warning_message="Did not find any indicator for any detection. Maybe something is wrong."),
            mlog,
        )
        return case_file

    # Add the context to the detection case
    if len(network_contexts) > 0:
        for network_context in network_contexts:
            case_file.add_context(network_context)

    if len(process_contexts) > 0:
        for process_context in process_contexts:
            case_file.add_context(process_context)

    #                                                       #
    ## Step 2 - Add note toiris-caseof the detection case ##
    #

    detection_str = "detection"
    if len(case_file.detections) > 1:
        detection_str += "s"

    if len(network_contexts) > 0 or len(process_contexts) > 0:
        current_action = AuditLog(PB_NAME, 5, "Adding note to iris-case", "Started adding note to iris-case")
        case_file.update_audit(current_action, mlog)
        try:
            note_title = f"Context: Threat Intel (VirusTotal)"
            hits_sus = []
            for context in network_contexts:
                if context:
                    hits_sus.append(context) if context.score_hit_sus > 0 else None
            for context in process_contexts:
                if context:
                    hits_sus.append(context) if context.score_hit_sus > 0 else None

            hits_mal = []
            for context in network_contexts:
                if context:
                    hits_mal.append(context) if context.score_hit_mal > 0 else None
            for context in process_contexts:
                if context:
                    hits_mal.append(context) if context.score_hit_mal > 0 else None

            note_body = "<h2>Highlights (Hits)</h2>"
            note_body += f"Found {str(len(hits_sus))} suspicious and {str(len(hits_mal))} malicious hit(s).<br><br>"
            note_body += f"<h3>Suspicious hits:</h3><br><br>"
            note_body += format_results(hits_sus, "html", "")
            note_body += f"<h3>Malicious hits:</h3><br><br>"
            note_body += format_results(hits_mal, "html", "")
            note_body += "<br><br><br><br>"
            note_body += "<h2>Complete Context</h2>"
            note_body += f"Found {str(len(network_contexts))} network threat intel and {str(len(process_contexts))} process threat intel from VirusTotal for this {detection_str}.<br><br>"
            note_body += f"<h3>Process threat intel:</h3><br><br>"
            note_body += format_results(process_contexts, "html", "")
            note_body += f"<h3>Network threat intel:</h3><br><br>"
            note_body += format_results(network_contexts, "html", "")
            note_body += "<br><br><br><br>"

            zs_add_note_to_iris_case(iris_case_number, "raw", TEST, note_title, note_body, "text/html")
            current_action.playbook_done = True
            case_file.update_audit(
                current_action.set_successful(message=f"Added note to iris-case", data=case_file.detections), mlog
            )
        except Exception as e:
            mlog.error(f"Error while adding note to iris-case: {e}")
            case_file.update_audit(current_action.set_error(message=f"Error while adding note to iris-case: {e}", data=e), mlog)
    else:
        mlog.info(f"No threat intel found for this {detection_str}. Not adding note to iris_case.")

    return case_file
