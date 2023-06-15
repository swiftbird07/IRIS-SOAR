# Playbook for Z-SOAR
# Created by: Martin Offermann
#
# This is a playbook used by Z-SOAR
# It is used to generally handle detections to add VirusTotal context to them.
#
# Acceptable Detections:
#  - All detections that have any kind of indicator that is searchable in VirusTotal
#
# Gathered Context:
# - VirusTotal context for the provided indicators
#
# Actions:
# - Add notes to related tickets
#
PB_NAME = "PB_010_Generic_VirusTotal"
PB_VERSION = "0.0.1"
PB_AUTHOR = "Martin Offermann"
PB_LICENSE = "MIT"
PB_ENABLED = True
from typing import Union, List
import ipaddress

import lib.logging_helper as logging_helper
from lib.class_helper import DetectionReport, ContextProcess, AuditLog, Detection, ContextThreatIntel, DNSQuery, HTTP
from lib.config_helper import Config
from lib.generic_helper import cast_to_ipaddress, format_results, is_local_tld

from integrations.virus_total import zs_provide_context_for_detections
from integrations.znuny_otrs import zs_add_note_to_ticket, zs_get_ticket_by_number

# Prepare the logger
cfg = Config().cfg
log_level_file = cfg["integrations"]["elastic_siem"]["logging"]["log_level_file"]
log_level_stdout = cfg["integrations"]["elastic_siem"]["logging"]["log_level_stdout"]
mlog = logging_helper.Log("playbooks." + PB_NAME, log_level_file, log_level_stdout)

def zs_can_handle_detection(detection_report: DetectionReport) -> bool:
    """Checks if this playbook can handle the detection.

    Args:
        detection_report (DetectionReport): The detection report

    Returns:
        bool: True if the playbook can handle the detection, False if not
    """
    # Check if any of the detecions of the detection report is an Elastic Alert
    if PB_ENABLED == False:
        mlog.info(f"Playbook '{PB_NAME}' is disabled. Not handling anything.")
        return False
    
    # Check if there is already a ticket for the detection report
    try:
        ticket_number = detection_report.get_ticket_number()
    except ValueError:
        mlog.info(f"Playbook '{PB_NAME}' cannot handle detection report '{detection_report.uuid}' as there is no ticket for it.")
        return False
    
    # Check if any of the detecions of the detection report is an Elastic Alert
    for detection in detection_report.detections:
        if len(detection.indicators["ip"]) > 0 or len(detection.indicators["domain"]) > 0 or len(detection.indicators["url"]) > 0 or len(detection.indicators["hash"]) > 0:
            mlog.info(f"Playbook '{PB_NAME}' can handle detection '{detection.name}' ({detection.uuid}).")
            return True
    return False

def zs_handle_detection(detection_report: DetectionReport, TEST=False) -> DetectionReport:
    """Handles the detection.

    Args:
        detection_report (DetectionReport): The detection report
        TEST (bool): True if the playbook is run in test mode, False if not

    Returns:
        DetectionReport: The updated detection report
    """
    # Get all the indicators
    cfg = Config().cfg
    integration_config = cfg["integrations"]["virus_total"]
    mlog.info(f"Handling detection report '{detection_report.uuid}'")
    init_action = AuditLog(PB_NAME, 0, "Handling detection report", "Started handling detection report by getting indicators")
    detection_report.update_audit(init_action, mlog)

    indicators: List[str] = []
    network_contexts: List[ContextThreatIntel] = []
    process_contexts: List[ContextThreatIntel] = []

    try:
        ticket_number = detection_report.get_ticket_number()
    except ValueError: # Sanity check. Should not be raised, as zs_can_handle_detection() should have been called before to check if the detection report has a ticket number
        mlog.critical(f"Could not get ticket number from detection report. A ticket for the detection report must be created by a previous playbook for this playbook to work.")
        detection_report.update_audit(init_action.set_error(message="Could not get ticket number from detection report. A ticket for the detection report must be created by a previous playbook for this playbook to work."), mlog)
        return detection_report

    #                                                                      #
    ## STEP 1 - Get the threat intel for the indicators of all detections ##
    #                                                                      #

    for detection in detection_report.detections:
        mlog.info(f"Handling detection '{detection.name}' ({detection.uuid})")

        # Get the indicators
        mlog.debug(f"Found indicators of detection: {detection.indicators}")
        detection: Detection = detection
        ips = detection.indicators["ip"]
        domains = detection.indicators["domain"]
        urls = detection.indicators["url"]
        hashes = detection.indicators["hash"]

        if len(ips) > 0 or len(domains) > 0 or len(urls) > 0 or len(hashes) > 0:
            detection_report.update_audit(init_action.set_successful("Got indicators", data=detection.indicators), mlog)
        else:
            detection_report.update_audit(init_action.set_warning(warning_message=f"No indicators were found for detection {detection.name}."), mlog)
            continue

        if len(ips) > 0:
            mlog.debug(f"Found IPs: {ips}. Handling them.")
            current_action = AuditLog(PB_NAME, 1, "Handling IPs", "Started handling IPs")
            detection_report.update_audit(current_action, mlog)
            for ip in ips:
                ip = cast_to_ipaddress(ip)

                if ip.is_private:
                    mlog.debug(f"IP '{ip}' is private. Skipping it.")
                    continue

                try:
                    nw_new = zs_provide_context_for_detections(integration_config, detection_report, required_type=ContextThreatIntel, TEST=TEST, search_type=type(ip), search_value=ip, maxContext=1, wait_if_api_quota_exceeded=True)
                    if nw_new:
                        network_contexts.append(nw_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for IP '{ip}': {e}")
                    detection_report.update_audit(current_action.set_error(warning_message=f"Error while getting context for IP '{ip}': {e}", data=e), mlog)

            if len(network_contexts) != 0:
                detection_report.update_audit(current_action.set_successful(message=f"Got threat intel for {str(len(network_contexts))} out of {str(len(ips))} IPs", data=ips), mlog)
            else:
                # Check if all IPs were private
                had_public_ips = False
                for ip in ips:
                    ip = cast_to_ipaddress(ip)
                    if ip.is_global:
                        had_public_ips = True
                        break
                if had_public_ips:
                    detection_report.update_audit(current_action.set_warning(warning_message=f"Could not get threat intel for any of the {str(len(ips))} IPs", data=ips), mlog)
                else:
                    detection_report.update_audit(current_action.set_successful(message=f"All {str(len(ips))} IPs were private. No threat intel search possible for them.", data=ips), mlog)
        
        if len(domains) > 0:
            mlog.debug(f"Found domains: {domains}. Handling them.")
            current_action = AuditLog(PB_NAME, 2, "Handling domains", "Started handling domains")
            detection_report.update_audit(current_action, mlog)
            for domain in domains:
                try:
                    if is_local_tld(domain):
                        mlog.debug(f"Domain '{domain}' is a local domain. Skipping it.")
                        continue
                    domain_new = zs_provide_context_for_detections(integration_config, detection_report, required_type=ContextThreatIntel, TEST=TEST, search_type=DNSQuery, search_value=domain, maxContext=1, wait_if_api_quota_exceeded=True)
                    if domain_new:
                        network_contexts.append(domain_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for domain '{domain}': {e}")
                    detection_report.update_audit(current_action.set_error(warning_message=f"Error while getting context for domain '{domain}': {e}", data=e), mlog)

            if len(network_contexts) != 0:
                detection_report.update_audit(current_action.set_successful(message=f"Got threat intel for {str(len(network_contexts))} out of {str(len(domains))} domains", data=domains), mlog)
            else:
                detection_report.update_audit(current_action.set_warning(warning_message=f"Could not get threat intel for any of the {str(len(domains))} domains", data=domains), mlog)
        
        if len(urls) > 0:
            mlog.debug(f"Found URLs: {urls}. Handling them.")
            current_action = AuditLog(PB_NAME, 3, "Handling URLs", "Started handling URLs")
            detection_report.update_audit(current_action, mlog)
            for url in urls:
                try:
                    if is_local_tld(url.split("/")[2]):
                        mlog.debug(f"URL '{url}' is a local domain. Skipping it.")
                        continue
                    url_new = zs_provide_context_for_detections(integration_config, detection_report, required_type=ContextThreatIntel, TEST=TEST, search_type=HTTP, search_value=url, maxContext=1, wait_if_api_quota_exceeded=True)
                    if url_new:
                        network_contexts.append(url_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for URL '{url}': {e}")
                    detection_report.update_audit(current_action.set_error(warning_message=f"Error while getting context for URL '{url}': {e}", data=e), mlog)

            if len(network_contexts) != 0:
                detection_report.update_audit(current_action.set_successful(message=f"Got threat intel for {str(len(network_contexts))} out of {str(len(urls))} URLs", data=urls), mlog)
            else:
                detection_report.update_audit(current_action.set_warning(warning_message=f"Could not get threat intel for any of the {str(len(urls))} URLs", data=urls), mlog)

        if len(hashes) > 0:
            mlog.debug(f"Found hashes: {hashes}. Handling them.")
            current_action = AuditLog(PB_NAME, 4, "Handling hashes", "Started handling hashes")
            detection_report.update_audit(current_action, mlog)
            for hash in hashes:
                try:
                    pc_new = zs_provide_context_for_detections(integration_config, detection_report, required_type=ContextThreatIntel, TEST=TEST, search_type=ContextProcess, search_value=hash, maxContext=1, wait_if_api_quota_exceeded=True)
                    if pc_new:
                        process_contexts.append(pc_new)
                except Exception as e:
                    mlog.error(f"Error while getting context for hash '{hash}': {e}")
                    detection_report.update_audit(current_action.set_error(warning_message=f"Error while getting context for hash '{hash}': {e}", data=e), mlog)

            if len(process_contexts) != 0:
                detection_report.update_audit(current_action.set_successful(message=f"Got threat intel for {str(len(process_contexts))} out of {str(len(hashes))} hashes", data=hashes), mlog)
            else:
                detection_report.update_audit(current_action.set_warning(warning_message=f"Could not get threat intel for any of the {str(len(hashes))} hashes", data=hashes), mlog)

        if len(ips) == 0 and len(domains) == 0 and len(urls) == 0 and len(hashes) == 0:
            mlog.info("No indicators found in this detection.")
        elif len(network_contexts) == 0 and len(process_contexts) == 0:
            mlog.info("Found indicators, but no threat intel for this detection.")
        else:
            mlog.info(f"Found {str(len(network_contexts))} network indicators and {str(len(process_contexts))} process indicators for this detection.")

    if not init_action.result_was_successful:
        detection_report.update_audit(init_action.set_warning(warning_message="Did not find any indicator for any detection. Maybe something is wrong."), mlog)
        return detection_report
    
    # Add the context to the detection report
    if len(network_contexts) > 0:
        for network_context in network_contexts:
            detection_report.add_context(network_context)

    if len(process_contexts) > 0:
        for process_context in process_contexts:
            detection_report.add_context(process_context)
    
    #                                                       #
    ## Step 2 - Add note to ticket of the detection report ##
    #    

    detection_str = "detection"
    if len(detection_report.detections) > 1:
        detection_str += "s"
    
    if len(network_contexts) > 0 or len(process_contexts) > 0:
        current_action = AuditLog(PB_NAME, 5, "Adding note to ticket", "Started adding note to ticket")
        detection_report.update_audit(current_action, mlog)
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

            zs_add_note_to_ticket(ticket_number, "raw", TEST, note_title, note_body, "text/html")
            current_action.playbook_done = True
            detection_report.update_audit(current_action.set_successful(message=f"Added note to ticket", data=detection_report.detections), mlog)
        except Exception as e:
            mlog.error(f"Error while adding note to ticket: {e}")
            detection_report.update_audit(current_action.set_error(message=f"Error while adding note to ticket: {e}", data=e), mlog)
    else:
        mlog.info(f"No threat intel found for this {detection_str}. Not adding note to ticket.")
    
    return detection_report