# Z-SOAR
# Created by: Martin Offermann
# This module is a helper module that privides important classes and functions for the Z-SOAR project.

from typing import DefaultDict, Union, List
import random
import datetime
import ipaddress
import datetime
import json
import uuid
import pandas as pd
import pyotrs

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
from lib.generic_helper import (
    del_none_from_dict,
    handle_percentage,
    cast_to_ipaddress,
    add_to_timeline,
    remove_duplicates_from_dict,
    dict_get,
)

DEFAULT_IP = ipaddress.ip_address("127.0.0.1")  # When no IP address is provided, this is used
THRESHOLD_PROCESS_IO_BYTES = 100000  # Threshold for the process IO bytes (100 KB)

# TODO: Implement all functions used by zsoar_worker.py and its modules


class Location:
    """Location class. This class is used for storing location information.

    Attributes:
        country (str): The country of the location
        city (str): The city of the location
        latitude (float): The latitude of the location
        longitude (float): The longitude of the location
        timezone (str): The timezone of the location
        asn (int): The ASN of the location
        asn_corperation (str): The ASN corperation of the location
        org (str): The organization of the location
        certainty (int): The certainty of the location. This has to be a percentage value between 0 and 100 (inclusive)
        last_updated (datetime): The date and time when the location was last updated
        uuid (str): The UUID of the location

    Methods:
        __dict__(self): Returns the dictionary representation of the Location object.
        __str__(self): Returns the string representation of the Location object.
    """

    def __init__(
        self,
        country: str = None,
        city: str = None,
        latitude: float = None,
        longitude: float = None,
        timezone: str = None,
        asn: int = None,
        asn_corperation: str = None,
        org: str = None,
        certainty: int = None,
        last_updated: datetime = None,
        uuid: str = str(uuid.uuid4()),
    ):
        # Check that at least one of the parameters is not None
        if (
            country is None
            and city is None
            and latitude is None
            and longitude is None
            and timezone is None
            and asn is None
            and asn_corperation is None
            and org is None
        ):
            raise ValueError("At least one parameter must be set")

        self.country = country
        self.city = city
        self.latitude = latitude
        self.longitude = longitude
        self.timezone = timezone
        self.asn = asn
        self.asn_corperation = asn_corperation
        self.org = org

        self.certainty = handle_percentage(certainty)
        self.last_updated = last_updated

        if not last_updated:
            self.timestamp = datetime.datetime.now()  # when the object was created (for cross-context compatibility)
        else:
            self.timestamp = last_updated

        self.uuid = uuid

    def __dict__(self):
        """Returns the dictionary representation of the Location object."""
        dict_ = {
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "asn": self.asn,
            "asn_corperation": self.asn_corperation,
            "org": self.org,
            "certainty": self.certainty,
            "last_updated": str(self.last_updated),
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the Vulnerability object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    def is_valid(self):
        """Returns whether the Location object is valid or not."""
        if self.country is not None:
            return True

        if self.latitude is not None and self.longitude is not None:
            return True

        if self.org is not None:
            return True

        return False


class Vulnerability:
    """Vulnerability class. This class is used for storing vulnerability information.

    Attributes:
        cve (str): The CVE ID of the vulnerability
        description (str): The description of the vulnerability
        tags (List[str]): A list of tags for the vulnerability
        created_at (datetime): The date and time when the vulnerability was created
        updated_at (datetime): The date and time when the vulnerability was last updated
        cvss (float): The CVSS score of the vulnerability
        cvss_vector (str): The CVSS vector of the vulnerability
        cvss3 (float): The CVSS3 score of the vulnerability
        cvss3_vector (str): The CVSS3 vector of the vulnerability
        cwe (str): The CWE ID of the vulnerability
        references (List[str]): A list of references for the vulnerability
        exploit_available (bool): Whether an exploit is available for the vulnerability
        exploit_frameworks (List[str]): A list of exploit frameworks for the vulnerability
        exploit_mitigations (List[str]): A list of exploit mitigations for the vulnerability
        exploitability_ease (str): The exploitability ease of the vulnerability
        published_at (datetime): The date and time when the vulnerability was published
        last_modified_at (datetime): The date and time when the vulnerability was last modified
        patched_at (datetime): The date and time when the vulnerability was patched
        solution (str): The solution for the vulnerability
        solution_date (datetime): The date and time when the solution was published
        solution_type (str): The type of the solution
        solution_link (str): The link to the solution
        solution_description (str): The description of the solution
        solution_tags (List[str]): A list of tags for the solution
        services_affected (List[Service]): A list of services affected by the vulnerability
        services_vulnerable (List[Service]): A list of services vulnerable to the vulnerability
        attack_vector (str): The attack vector of the vulnerability
        attack_complexity (str): The attack complexity of the vulnerability
        privileges_required (str): The privileges required for the vulnerability
        user_interaction (str): Whether user interaction is required for the vulnerability
        confidentiality_impact (str): The confidentiality impact of the vulnerability
        integrity_impact (str): The integrity impact of the vulnerability
        availability_impact (str): The availability impact of the vulnerability
        scope (str): The scope of the vulnerability
        version (str): The version of the scoring system used for the vulnerability
        uuid (str): The UUID of the vulnerability

    Methods:
        __init__(self, name: str, description: str = None, tags: List[str] = None, created_at: datetime = None, updated_at: datetime = None, cve: str = None, cvss: float = None, cvss_vector: str = None, cvss3: float = None, cvss3_vector: str = None, cwe: str = None, references: List[str] = None, exploit_available: bool = None, exploit_frameworks: List[str] = None, exploit_mitigations: List[str] = None, exploitability_ease: str = None, published_at: datetime = None, last_modified_at: datetime = None, patched_at: datetime = None, solution: str = None, solution_date: datetime = None, solution_type: str = None, solution_link: str = None, solution_description: str = None, solution_tags: List[str] = None, services_affected: List[Service] = None, services_vulnerable: List[Service] = None, attack_vector: str = None, attack_complexity: str = None, privileges_required: str = None, user_interaction: str = None, confidentiality_impact: str = None, integrity_impact: str = None, availability_impact: str = None, scope: str = None)
        __dict__(self)
        __str__(self)
    """

    def __init__(
        self,
        cve: str,
        description: str = None,
        tags: List[str] = None,
        created_at: datetime = None,
        updated_at: datetime = None,
        cvss: float = None,
        cvss_vector: str = None,
        cvss3: float = None,
        cvss3_vector: str = None,
        cwe: str = None,
        references: List[str] = None,
        exploit_available: bool = None,
        exploit_frameworks: List[str] = [],
        exploit_mitigations: List[str] = [],
        exploitability_ease: str = None,
        published_at: datetime = None,
        last_modified_at: datetime = None,
        patched_at: datetime = None,
        solution: str = None,
        solution_date: datetime = None,
        solution_type: str = None,
        solution_url: str = None,
        solution_advisory: str = None,
        solution_advisory_url: str = None,
        services_affected: List = [],  # type is Service for each item
        services_vulnerable: List = [],  # type is Service for each item
        attack_vector: str = None,
        attack_complexity: str = None,
        privileges_required: str = None,
        user_interaction: str = None,
        confidentiality_impact: str = None,
        integrity_impact: str = None,
        availability_impact: str = None,
        scope: str = None,
        version: str = None,
        uuid: str = str(uuid.uuid4()),
    ):
        self.description = description
        self.tags = tags
        self.created_at = created_at
        self.updated_at = updated_at
        self.cve = cve
        self.cvss = cvss
        self.cvss_vector = cvss_vector
        self.cvss3 = cvss3
        self.cvss3_vector = cvss3_vector
        self.cwe = cwe
        self.references = references
        self.exploit_available = exploit_available
        self.exploit_frameworks = exploit_frameworks
        self.exploit_mitigations = exploit_mitigations
        self.exploitability_ease = exploitability_ease
        self.published_at = published_at
        self.last_modified_at = last_modified_at
        self.patched_at = patched_at
        self.solution = solution
        self.solution_date = solution_date
        self.solution_type = solution_type
        self.solution_url = solution_url
        self.solution_advisory = solution_advisory
        self.solution_advisory_url = solution_advisory_url
        self.services_affected = services_affected

        if services_vulnerable is None:
            self.services_vulnerable = services_affected
        else:
            for service in services_vulnerable:
                if not isinstance(service, Service):
                    raise TypeError("services_vulnerable must be a subset of services_affected")
            self.services_vulnerable = services_vulnerable

        if services_affected is None:
            self.services_affected = services_vulnerable
        else:
            for service in services_affected:
                if not isinstance(service, Service):
                    raise TypeError("services_affected must be a subset of services_vulnerable")
            self.services_affected = services_affected

        self.attack_vector = attack_vector
        self.attack_complexity = attack_complexity
        self.privileges_required = privileges_required
        self.user_interaction = user_interaction
        self.confidentiality_impact = confidentiality_impact
        self.integrity_impact = integrity_impact
        self.availability_impact = availability_impact
        self.scope = scope
        self.version = version
        self.uuid = uuid

    def __dict__(self):
        dict_ = {
            "cve": self.cve,
            "description": self.description,
            "tags": self.tags,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "cvss3": self.cvss3,
            "cvss3_vector": self.cvss3_vector,
            "cwe": self.cwe,
            "references": self.references,
            "exploit_available": self.exploit_available,
            "exploit_frameworks": self.exploit_frameworks,
            "exploit_mitigations": self.exploit_mitigations,
            "exploitability_ease": self.exploitability_ease,
            "published_at": str(self.published_at),
            "last_modified_at": str(self.last_modified_at),
            "patched_at": str(self.patched_at),
            "solution": self.solution,
            "solution_date": str(self.solution_date),
            "solution_type": self.solution_type,
            "solution_url": self.solution_url,
            "solution_advisory": self.solution_advisory,
            "solution_advisory_url": self.solution_advisory_url,
            "services_affected": [str(service) for service in self.services_affected],
            "services_vulnerable": [str(service) for service in self.services_vulnerable],
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "confidentiality_impact": self.confidentiality_impact,
            "integrity_impact": self.integrity_impact,
            "availability_impact": self.availability_impact,
            "scope": self.scope,
            "version": self.version,
            "uuid": self.uuid,
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the Vulnerability object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class Service:
    """Service class. This class is used for storing service information.
       ! This class is not a stand-alone context. !
       Use it in a Device context if a device is running a service.

    Attributes:
        name (str): The name of the service
        vendor (str, optional): The vendor of the service. Defaults to None.
        description (str, optional): The description of the service. Defaults to None.
        tags (List[str], optional): A list of tags for the service. Defaults to None.
        created_at (datetime, optional): The date and time when the service was created. Defaults to None.
        updated_at (datetime, optional): The date and time when the service was last updated. Defaults to None.
        current_vulnerabilities (List[Vulnerability], optional): A list of current vulnerabilities. Defaults to None.
        fixed_vulnerabilities (List[Vulnerability], optional): A list of fixed vulnerabilities. Defaults to None.
        installed_version (str, optional): The installed version of the service. Defaults to None.
        latest_version (str, optional): The latest version of the service. Defaults to None.
        outdated (bool, optional): Whether the service is outdated. Defaults to None.
        ports (List[int], optional): A list of ports the service is running on. Defaults to None.
        protocol (str, optional): The protocol the service is using. Defaults to None.
        required_availability (int, optional): The required availability of the service. Defaults to None.
        required_confidentiality (int, optional): The required confidentiality of the service. Defaults to None.
        required_integrity (int, optional): The required integrity of the service. Defaults to None.
        colleteral_damage_potential (int, optional): The potential damage of the service. Defaults to None.
        impact_score (int, optional): The impact score of the service. Defaults to None.
        risk_score (int, optional): The risk score of the service. Defaults to None.
        risk_score_vector (str, optional): The risk score vector of the service. Defaults to None.
        child_services (List[Service], optional): A list of child services. Defaults to None.
        parent_services (List[Service], optional): A list of parent services. Defaults to None.
        uuid (str, optional): The UUID of the service. Defaults to a random UUID.

        Be aware that every 'int' attribute has to be a percentage value between 0 and 100 (inclusive).

    Methods:
        __init__(): Initializes the Service class
        __dict__(): Converts the Service class to a dictionary
        __str__(): Converts the Service class to a string
    """

    def __init__(
        self,
        name: str,
        vendor: str = None,
        description: str = None,
        tags: List[str] = [],
        created_at: datetime = None,
        updated_at: datetime = None,
        current_vulnerabilities: List[Vulnerability] = [],
        fixed_vulnerabilities: List[Vulnerability] = [],
        installed_version: str = None,
        latest_version: str = None,
        outdated: bool = None,
        ports: List[int] = [],
        protocol: str = None,
        required_availability: int = None,
        required_confidentiality: int = None,
        required_integrity: int = None,
        colleteral_damage_potential: int = None,
        impact_score: int = None,
        risk_score: int = None,
        risk_score_vector: str = None,
        child_services: List = [],  # type is Service for each item
        parent_services: List = [],  # type is Service for each item
        uuid: uuid = uuid.uuid4(),
    ):
        self.name = name
        self.vendor = vendor
        self.description = description
        self.tags = tags
        self.created_at = created_at
        self.updated_at = updated_at
        self.current_vulnerabilities = current_vulnerabilities
        self.fixed_vulnerabilities = fixed_vulnerabilities
        self.installed_version = installed_version
        self.latest_version = latest_version
        self.outdated = outdated
        self.ports = ports
        self.protocol = protocol
        self.required_availability = handle_percentage(required_availability)
        self.required_confidentiality = handle_percentage(required_confidentiality)
        self.required_integrity = handle_percentage(required_integrity)
        self.colleteral_damage_potential = handle_percentage(colleteral_damage_potential)
        self.impact_score = handle_percentage(impact_score)
        self.risk_score = handle_percentage(risk_score)
        self.risk_score_vector = risk_score_vector

        if child_services is None:
            self.child_services = []
        else:
            for service in child_services:
                if not isinstance(service, Service):
                    raise TypeError("Child services must be of type Service")
            self.child_services = child_services

        if parent_services is None:
            self.parent_services = []
        else:
            for service in parent_services:
                if not isinstance(service, Service):
                    raise TypeError("Parent services must be of type Service")
            self.parent_services = parent_services

        self.uuid = uuid

    def __dict__(self):
        """Converts the Service class to a dictionary."""

        dict_ = {
            "name": self.name,
            "vendor": self.vendor,
            "description": self.description,
            "tags": self.tags,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
            "current_vulnerabilities": [str(vuln) for vuln in self.current_vulnerabilities],
            "fixed_vulnerabilities": [str(vuln) for vuln in self.fixed_vulnerabilities],
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "outdated": self.outdated,
            "ports": self.ports,
            "protocol": self.protocol,
            "required_availability": str(self.required_availability),
            "required_confidentiality": str(self.required_confidentiality),
            "required_integrity": str(self.required_integrity),
            "colleteral_damage_potential": str(self.colleteral_damage_potential),
            "impact_score": str(self.impact_score),
            "risk_score": str(self.risk_score),
            "risk_score_vector": self.risk_score_vector,
            "child_services": [str(service) for service in self.child_services],
            "parent_services": [str(service) for service in self.parent_services],
            "uuid": str(self.uuid),
        }

        return dict_

    def __str__(self) -> str:
        """Returns the Person class as a string."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class Person:
    """Person class. This class is used for storing person information.

    Attributes:
        name (str): The name of the person
        email (str): The email address of the person
        phone (str): The phone number of the person
        tags (List[str]): A list of tags assigned to the person
        created_at (datetime): The date and time when the person was created
        updated_at (datetime): The date and time when the person was last updated
        primary_location (Location): The primary location of the person
        locations (List[Location]): A list of locations of the person
        roles (List[str]): A list of roles assigned to the person
        access_to (List[Device]): A list of devices the person has access to
        uuid (uuid): The UUID of the person

    Methods:
        __init__(): Initializes the Person class
        __dict__(): Converts the Person class to a dictionary
        __str__(): Converts the Person class to a string
    """

    def __init__(
        self,
        name: str,
        email: str = None,
        phone: str = None,
        tags: List[str] = [],
        created_at: datetime = None,
        updated_at: datetime = None,
        primary_location: Location = None,
        locations: List[Location] = [],
        roles: List[str] = [],
        access_to: List = [],  # type is 'Device' for each entry
        uuid: uuid.UUID = uuid.uuid4(),
    ):
        self.name = name
        self.email = email
        self.phone = phone
        self.tags = tags
        self.created_at = created_at
        self.updated_at = updated_at
        self.primary_location = primary_location
        self.locations = locations
        self.roles = roles
        self.access_to = access_to

        if not updated_at:
            self.timestamp = datetime.datetime.now()  # when the object was created (for cross-context compatibility)
        else:
            self.timestamp = updated_at

        self.uuid = uuid

    def __dict__(self):
        """Converts the Person class to a dictionary.

        Returns:
            dict: The dictionary representation of the Person class
        """
        return {
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "tags": self.tags,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
            "primary_location": str(self.primary_location),
            "locations": [str(location) for location in self.locations],
            "roles": self.roles,
            "access_to": [str(device) for device in self.access_to],
        }

    def __str__(self) -> str:
        """Returns the Person class as a string."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ContextDevice:
    """ContextDevice class. This class is used for storing contextual device information.

    Attributes:
        name (str): The name of the device
        local_ip (Union[ipaddress.IPv4Address, ipaddress.IPv6Address]): The local IP address of the device
        global_ip (Union[ipaddress.IPv4Address, ipaddress.IPv6Address]): The global IP address of the device
        ips (List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]): A list of all IP addresses of the device
        mac (str): The MAC address of the device
        vendor (str): The vendor of the device
        os (str): The operating system of the device
        os_version (str): The version of the operating system of the device
        os_family (str): The family of the operating system of the device
        os_last_update (datetime): The last update of the operating system of the device
        kernel (str): The kernel of the device
        in_scope (bool): Whether the device is in scope or not
        tags (List[str]): A list of tags assigned to the device
        created_at (datetime): The date and time when the device was created
        updated_at (datetime): The date and time when the device was last updated
        in_use (bool): Whether the device is in use or not
        type (str): The type of the device
        owner (Person): The owner of the device
        uuid (uuid.UUID): The UUID of the device
        aliases (List[str]): A list of aliases of the device
        description (str): The description of the device
        location (Location): The location of the device
        notes (str): The notes of the device
        last_seen (datetime): The date and time when the device was last seen
        first_seen (datetime): The date and time when the device was first seen
        last_scan (datetime): The date and time when the device was last scanned
        last_update (datetime): The date and time when the device properties were last updated
        user (List[Person]): A list of users of the device
        group (str): The group of the device
        auth_types (List[str]): A list of authentication types of the device
        auth_stored_in (List[str]): A list of authentication storages of the device
        stored_credentials (List[str]): A list of stored credentials of the device
        should_state (str): The state the device should be in
        is_state (str): The state the device is in
        is_state_reason (str): The reason why the device is in the state it is in
        hypervisor (Device): The hypervisor of the device
        virtualization_type (str): The virtualization type of the device
        virtual_locations (List[str]): A list of virtual locations of the device
        services (List[Service]): A list of services of the device
        vulnerabilities (List[Vulnerability]): A list of vulnerabilities of the device
        domains (List[str]): A list of domains of the device
        network (Union[ipaddress.IPv4Network, ipaddress.IPv6Network]): The network of the device
        interfaces (List[str]): A list of interfaces of the device
        ports (List[int]): A list of ports of the device
        protocols (List[str]): A list of protocols of the device

    Methods:
        __init__(self, name: str, local_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP, global_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP, ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = [], mac: str = None, vendor: str = None, os: str = None, os_version: str = None, os_family: str = None, os_last_update: datetime = None, in_scope: bool = True, tags: List[str] = None, created_at: datetime = None, updated_at: datetime = None, in_use: bool = True, type: str = None, owner: Person = None, uuid: uuid.UUID = None, aliases: List[str] = None, description: str = None, location: Location = None, notes: str = None, last_seen: datetime = None, first_seen: datetime = None, last_scan: datetime = None, last_update: datetime = None, user: List[Person] = None, group: str = None, auth_types: List[str] = None, auth_stored_in: List[str] = None, stored_credentials: List[str] = None, should_state: str = None, is_state: str = None, is_state_reason: str = None, hypervisor: Device = None, virtualization_type: str = None, virtual_locations: List[str] = None, services: List[Service] = None, vulnerabilities: List[Vulnerability] = None, domains: List[str] = None, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = None, interfaces: List[str] = None, ports: List[int] = None, protocols: List[str] = None)
        __str__(self)
        __dict__(self)
    """

    def __init__(
        self,
        name: str,
        local_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP,
        global_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP,
        ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = [],
        mac: str = None,
        vendor: str = None,
        os: str = None,
        os_version: str = None,
        os_family: str = None,
        os_last_update: datetime = None,
        kernel: str = None,
        in_scope: bool = True,
        tags: List[str] = None,
        created_at: datetime = None,
        updated_at: datetime = None,
        in_use: bool = True,
        type: str = None,
        owner: Person = None,
        uuid: uuid.UUID = None,
        aliases: List[str] = None,
        description: str = None,
        location: Location = None,
        notes: str = None,
        last_seen: datetime = None,
        first_seen: datetime = None,
        last_scan: datetime = None,
        last_update: datetime = None,
        user: List[Person] = [],
        group: str = None,
        auth_types: List[str] = None,
        auth_stored_in: List[str] = None,
        stored_credentials: List[str] = None,
        should_state: str = None,
        is_state: str = None,
        is_state_reason: str = None,
        hypervisor=None,  # can't state that here, but type has to be 'Device' as well
        virtualization_type: str = None,
        virtual_locations: List[str] = [],
        services: List[Service] = [],
        vulnerabilities: List[Vulnerability] = [],
        domains: List[str] = [],
        network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = None,
        interfaces: List[str] = [],
        ports: List[int] = [],
        protocols: List[str] = [],
    ):
        mlog = logging_helper.Log("lib.class_helper")

        self.name = name
        self.local_ip = cast_to_ipaddress(local_ip, strict=False)
        self.global_ip = cast_to_ipaddress(global_ip, strict=False)

        if ips is None:
            self.ips = []
        else:
            self.ips = [cast_to_ipaddress(ip) for ip in ips]

        self.mac = mac
        self.vendor = vendor
        self.os = os
        self.os_version = os_version
        self.os_family = os_family
        self.os_last_update = os_last_update
        self.kernel = kernel
        self.in_scope = in_scope
        self.tags = tags
        self.created_at = created_at
        self.updated_at = updated_at
        self.in_use = in_use
        self.type = type
        self.owner = owner
        self.uuid = uuid
        self.aliases = aliases
        self.description = description

        # Check if location objects are valid if given
        if location:
            if not isinstance(location, Location):
                raise TypeError("location must be of type Location")
            if not location.is_valid():
                raise ValueError("location is not valid")
        self.location = location

        self.notes = notes
        self.last_seen = last_seen
        self.first_seen = first_seen
        self.last_scan = last_scan
        self.last_update = last_update
        self.user = user
        self.group = group
        self.auth_types = auth_types
        self.auth_stored_in = auth_stored_in
        self.stored_credentials = stored_credentials
        self.should_state = should_state
        self.is_state = is_state
        self.is_state_reason = is_state_reason

        if hypervisor is not None:
            if type(hypervisor) == ContextDevice:
                self.hypervisor = hypervisor
            else:
                mlog.error("hypervisor has to be of type 'Device'")
                raise TypeError("hypervisor has to be of type 'Device'")
        else:
            self.hypervisor = None

        self.virtualization_type = virtualization_type
        self.virtual_locations = virtual_locations
        self.services = services
        self.vulnerabilities = vulnerabilities
        self.domains = domains

        if network is not None:
            if type(network) == ipaddress.IPv4Network or type(network) == ipaddress.IPv6Network:
                self.network = network
            else:
                self.network = ipaddress.ip_network(network)
        else:
            self.network = None

        self.interfaces = interfaces
        self.ports = ports
        self.protocols = protocols

        if self.local_ip == DEFAULT_IP and self.global_ip == DEFAULT_IP:
            mlog.error("No IP address was specified")
            raise ValueError("No IP address was specified")

        if not last_update:
            self.timestamp = datetime.datetime.now()  # when the object was created (for cross-context compatibility)
        else:
            self.timestamp = last_update

    def __dict__(self):
        """Returns the object as a dict."""

        dict_ = {
            "name": self.name,
            "local_ip": str(self.local_ip),
            "global_ip": str(self.global_ip),
            "ips": [str(ip) for ip in self.ips],
            "mac": self.mac,
            "vendor": self.vendor,
            "os": self.os,
            "os_version": self.os_version,
            "os_family": self.os_family,
            "os_last_update": self.os_last_update,
            "kernel": self.kernel,
            "in_scope": self.in_scope,
            "tags": self.tags,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
            "in_use": self.in_use,
            "type": self.type,
            "owner": str(self.owner),
            "uuid": self.uuid,
            "aliases": self.aliases,
            "description": self.description,
            "location": str(self.location),
            "notes": self.notes,
            "last_seen": str(self.last_seen),
            "first_seen": str(self.first_seen),
            "last_scan": str(self.last_scan),
            "last_update": str(self.last_update),
            "user": [str(user) for user in self.user],
            "group": self.group,
            "auth_types": self.auth_types,
            "auth_stored_in": self.auth_stored_in,
            "stored_credentials": self.stored_credentials,
            "should_state": self.should_state,
            "is_state": self.is_state,
            "is_state_reason": self.is_state_reason,
            "hypervisor": self.hypervisor,
            "virtualization_type": self.virtualization_type,
            "virtual_locations": self.virtual_locations,
            "services": [str(service) for service in self.services],
            "vulnerabilities": [str(vulnerability) for vulnerability in self.vulnerabilities],
            "domains": self.domains,
            "network": str(self.network),
            "interfaces": self.interfaces,
            "ports": self.ports,
            "protocols": self.protocols,
        }

        return dict_

    def __str__(self):
        """Returns the object as a string."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class Rule:
    """Rule class. This class is used for storing rules.

    Attributes:
        id (str): The ID of the rule
        name (str): The name of the rule
        description (str): The description of the rule
        severity (str): The severity of the rule
        risk_score (int): The risk score of the rule
        tags (List[str]): The tags of the rule
        raw (str): The raw rule
        created_at (datetime): The creation date of the rule
        updated_at (datetime): The last update date of the rule
        query (str): The query of the rule
        mitre_references (List[str]): The MITRE references of the rule
        known_false_positives (str): The known false positives of the rule

    Methods:
        __init__(self, id: str, name: str, severity: int, description: str = None, tags: List[str] = None, raw: str = None, created_at: datetime = None, updated_at: datetime = None)
        __str__(self)
    """

    def __init__(
        self,
        id: str,
        name: str,
        severity: str = None,
        risk_score: int = None,
        description: str = None,
        tags: List[str] = None,
        raw: str = None,
        created_at: datetime.datetime = None,
        updated_at: datetime.datetime = None,
        query: str = None,
        mitre_references: List[str] = None,
        known_false_positives: str = None,
    ):
        mlog = logging_helper.Log("lib.class_helper")

        if type(id) is not str:
            # mlog.warning("The ID of the rule is not a string: " + str(id) + ". Converting to string.")
            id = str(id)

        # TODO: (for all classes) Add type checks for strings as well

        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.risk_score = risk_score
        self.tags = tags
        self.raw = raw
        self.created_at = created_at
        self.updated_at = updated_at
        self.query = query
        self.mitre_references = mitre_references
        self.known_false_positives = known_false_positives

    def __dict__(self):
        """Returns the dictionary representation of the object."""
        dict_ = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "query": self.query,
            "mitre_references": self.mitre_references,
            "known_false_positives": self.known_false_positives,
            "tags": self.tags,
            "raw": self.raw,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    # ...


class Certificate:
    """Certificate class.
        ! This class is not a stand-alone context. !
       Use it in ContextProcess/File context if th certificate is a signature of a process/file. Use it in HTTP context if the certificate is related to https traffic.

    Attributes:
        related_detection_uuid (str): The UUID of the related detection
        subject (str): The subject of the certificate
        issuer (str): The issuer of the certificate
        issuer_common_name (str): The issuer common name of the certificate
        issuer_organization (str): The issuer organization of the certificate
        issuer_organizational_unit (str): The issuer organizational unit of the certificate
        serial_number (str): The serial number of the certificate
        subject_common_name (str): The subject common name of the certificate
        subject_organization (str): The subject organization of the certificate
        subject_organizational_unit (str): The subject organizational unit of the certificate
        subject_alternative_name (str): The subject alternative name of the certificate
        valid_from (datetime): The valid from of the certificate
        valid_to (datetime): The valid to of the certificate
        version (str): The version of the certificate
        signature_algorithm (str): The signature algorithm of the certificate
        public_key_algorithm (str): The public key algorithm of the certificate
        public_key_size (int): The public key size of the certificate
        is_trusted (bool): If the certificate is trusted on the system
        is_self_signed (bool): If the certificate is self signed


    Methods:
        __init__(self, flow: ContextFlow, subject: str, issuer: str, issuer_common_name: str = None, issuer_organization: str = None, issuer_organizational_unit: str = None, serial_number: str = None, subject_common_name: str = None, subject_organization: str = None, subject_organizational_unit: str = None, subject_alternative_name: str = None, valid_from: datetime = None, valid_to: datetime = None, version: str = None, signature_algorithm: str = None, public_key_algorithm: str = None, public_key_size: int = None)
        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        subject: str,
        issuer: str,
        issuer_common_name: str = None,
        issuer_organization: str = None,
        issuer_organizational_unit: str = None,
        serial_number: str = None,
        subject_common_name: str = None,
        subject_organization: str = None,
        subject_organizational_unit: str = None,
        subject_alternative_names: List[str] = None,
        valid_from: datetime = None,
        valid_to: datetime = None,
        version: str = None,
        signature_algorithm: str = None,
        public_key_algorithm: str = None,
        public_key_size: int = None,
        is_trusted: bool = None,
        is_self_signed: bool = None,
    ):
        self.related_detection_uuid = related_detection_uuid
        self.issuer = issuer
        self.issuer_common_name = issuer_common_name
        self.issuer_organization = issuer_organization
        self.issuer_organizational_unit = issuer_organizational_unit
        self.serial_number = serial_number
        self.subject = subject
        self.subject_common_name = subject_common_name
        self.subject_organization = subject_organization
        self.subject_organizational_unit = subject_organizational_unit
        self.subject_alternative_names = subject_alternative_names

        if valid_from != None and valid_to != None:
            if valid_from > valid_to:
                raise ValueError("valid_from must be before valid_to")

        self.valid_from = valid_from
        self.valid_to = valid_to
        self.version = version
        self.signature_algorithm = signature_algorithm
        self.public_key_algorithm = public_key_algorithm

        if public_key_size != None and public_key_size < 0:
            raise ValueError("public_key_size must be positive")

        self.public_key_size = public_key_size
        self.timestamp = datetime.datetime.now()  # when the object was created (for cross-context compatibility)

        self.is_trusted = is_trusted
        self.is_self_signed = is_self_signed

    def __dict__(self):
        dict_ = {
            "timestamp": self.timestamp,
            "related_detection_uuid": self.related_detection_uuid,
            "subject": self.subject,
            "issuer": self.issuer,
            "issuer_common_name": self.issuer_common_name,
            "issuer_organization": self.issuer_organization,
            "issuer_organizational_unit": self.issuer_organizational_unit,
            "serial_number": self.serial_number,
            "subject_common_name": self.subject_common_name,
            "subject_organization": self.subject_organization,
            "subject_organizational_unit": self.subject_organizational_unit,
            "subject_alternative_names": self.subject_alternative_names,
            "valid_from": str(self.valid_from),
            "valid_to": str(self.valid_to),
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_size": self.public_key_size,
            "is_trusted": self.is_trusted,
            "is_self_signed": self.is_self_signed,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ContextFile:
    """File class. Represents a file event in the context of a detection.

    Attributes:
        related_detection_uuid (uuid.UUID): The UUID of the detection the file is related to
        timestamp (datetime): When the object was created (for cross-context compatibility)
        action (str): The action that was performed on the file (create, modify, delete, rename, etc.)
        file_name (str): The name of the file
        file_original_name (str): The original name of the file (if renamed)
        file_path (str): The path of the file
        file_original_path (str): The original path of the file (if moved)
        file_size (int): The size of the file
        file_md5 (str): The MD5 hash of the file
        file_sha1 (str): The SHA1 hash of the file
        file_sha256 (str): The SHA256 hash of the file
        file_type (str): The type of the file
        file_extension (str): The extension of the file
        file_signature (Certificate): The signature of the file
        file_header_bytes (str): The first bytes of the file
        file_entropy (float): The entropy of the file
        process_name (str): The name of the process that created the file
        process_id (int): The ID of the process that created the file
        process_uuid (uuid.UUID): The UUID of the process that created the file
        last_modified (datetime): The last modified time of the file
        is_encrypted (bool): Whether the file is encrypted
        is_compressed (bool): Whether the file is compressed
        is_archive (bool): Whether the file is an archive
        is_executable (bool): Whether the file is executable
        is_readable (bool): Whether the file is readable
        is_writable (bool): Whether the file is writable
        is_hidden (bool): Whether the file is hidden
        is_system (bool): Whether the file is a system file
        is_temporary (bool): Whether the file is a temporary file
        is_virtual (bool): Whether the file is a virtual file
        is_directory (bool): Whether the file is a directory
        is_symlink (bool): Whether the file is a symlink
        is_special (bool): Whether the file is a special file (socket, pipe, pid, etc.)
        is_unknown (bool): Whether the file has unknown type or content
        uuid (uuid.UUID): The UUID of the file

    Methods:
        __init__(self, file_name: str, file_path: str, file_size: int, file_md5: str, file_sha1: str, file_sha256: str,
            file_type: str, file_extension: str, is_encrypted: bool, is_compressed: bool, is_archive: bool, is_executable: bool,
            is_readable: bool, is_writable: bool, is_hidden: bool, is_system: bool, is_temporary: bool, is_virtual: bool,
            is_directory: bool, is_symlink: bool, is_special: bool, is_unknown: bool): The constructor of the ContextFile class
        __str__(self): The string representation of the ContextFile class
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        timestamp: datetime,
        action: str,
        file_name: str,
        file_original_name: str = "",
        file_path: str = "",
        file_original_path: str = "",
        file_size: int = 0,
        file_md5: str = "",
        file_sha1: str = "",
        file_sha256: str = "",
        file_type: str = "",
        file_extension: str = "",
        file_signature: Certificate = None,
        file_header_bytes: str = "",
        file_entropy: float = 0.0,
        process_name: str = "",
        process_id: int = 0,
        process_uuid: uuid.UUID = None,
        last_modified: datetime = datetime.datetime(1970, 1, 1, 0, 0, 0),
        is_encrypted: bool = False,
        is_compressed: bool = False,
        is_archive: bool = False,
        is_executable: bool = False,
        is_readable: bool = False,
        is_writable: bool = False,
        is_hidden: bool = False,
        is_system: bool = False,
        is_temporary: bool = False,
        is_virtual: bool = False,
        is_directory: bool = False,
        is_symlink: bool = False,
        is_special: bool = False,
        is_unknown: bool = False,
        uuid: uuid.UUID = uuid.uuid4(),
    ):
        self.related_detection_uuid = related_detection_uuid
        self.timestamp = timestamp
        self.action = action

        if file_name and file_name.startswith("/") and len(file_name) > 1:  # ContextFile name should not start with a slash
            file_name = file_name[1:]
        self.file_name = file_name

        self.file_original_name = file_original_name
        self.file_path = file_path
        self.file_original_path = file_original_path

        if file_size and file_size < -1:
            raise ValueError("file_size must not be negative")
        self.file_size = file_size

        self.file_md5 = file_md5
        self.file_sha1 = file_sha1
        self.file_sha256 = file_sha256

        self.file_type = file_type

        if (
            file_extension and file_extension != "" and file_extension[0] == "." and len(file_extension) > 1
        ):  # ContextFile extension should not start with a dot in the variable
            file_extension = file_extension[1:]
        self.file_extension = file_extension

        self.file_signature = file_signature

        self.process_name = process_name
        self.process_id = process_id
        self.process_uuid = process_uuid

        self.file_header_bytes = file_header_bytes
        self.file_entropy = file_entropy

        self.is_encrypted = is_encrypted
        self.is_compressed = is_compressed
        self.is_archive = is_archive
        self.is_executable = is_executable
        self.is_readable = is_readable
        self.is_writable = is_writable
        self.is_hidden = is_hidden
        self.is_system = is_system
        self.is_temporary = is_temporary
        self.is_virtual = is_virtual
        self.is_directory = is_directory
        self.is_symlink = is_symlink
        self.is_special = is_special
        self.is_unknown = is_unknown

        self.last_modified = last_modified
        self.timestamp = last_modified  # For cross-context compatibility
        self.uuid = uuid

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "timestamp": self.timestamp,
            "action": self.action,
            "file_name": self.file_name,
            "file_original_name": self.file_original_name,
            "file_path": self.file_path,
            "file_original_path": self.file_original_path,
            "file_size": self.file_size,
            "file_md5": self.file_md5,
            "file_sha1": self.file_sha1,
            "file_sha256": self.file_sha256,
            "file_type": self.file_type,
            "file_extension": self.file_extension,
            "file_signature": str(self.file_signature),
            "file_header_bytes": self.file_header_bytes,
            "file_entropy": str(self.file_entropy),
            "process_name": self.process_name,
            "process_id": self.process_id,
            "process_uuid": self.process_uuid,
            "is_encrypted": self.is_encrypted,
            "is_compressed": self.is_compressed,
            "is_archive": self.is_archive,
            "is_executable": self.is_executable,
            "is_readable": self.is_readable,
            "is_writable": self.is_writable,
            "is_hidden": self.is_hidden,
            "is_system": self.is_system,
            "is_temporary": self.is_temporary,
            "is_virtual": self.is_virtual,
            "is_directory": self.is_directory,
            "is_symlink": self.is_symlink,
            "is_special": self.is_special,
            "is_unknown": self.is_unknown,
            "last_modified": self.last_modified,
            "timestamp": self.timestamp,
            "uuid": self.uuid,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class DNSQuery:
    """DNSQuery class.

    Attributes:
        related_detection_uuid (str): The UUID of the related detection
        type (str): The type of the DNS query
        query (str): The query of the DNS query
        query_response (str): The query response of the DNS query
        rcode (str): The rcode of the DNS query

    Methods:
        __init__(self, flow: ContextFlow, type: str, query: str, query_response: str = None, rcode: str = "NOERROR")
        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        type: str,
        query: str,
        has_response: bool = False,
        query_response: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, str] = None,
        rcode: str = "NOERROR",
        timestamp=datetime.datetime.now(),
    ):
        self.related_detection_uuid = related_detection_uuid

        if type not in ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]:
            raise ValueError("type must be one of A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT")

        self.type = type
        self.query = query

        self.has_response = has_response

        if has_response and query_response == None:
            mlog = logging_helper.Log("lib.class_helper")
            mlog.warning("DNSQuery __init__: query_response is still DEFAULT_IP while has_response is True.", str(self))
        self.query_response = query_response

        self.rcode = rcode
        self.timestamp = timestamp

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "type": self.type,
            "query": self.query,
            "has_response": self.has_response,
            "query_response": str(self.query_response),
            "rcode": self.rcode,
            "timestamp": self.timestamp,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class HTTP:
    """HTTP class.

    Attributes:
        related_detection_uuid (str): The UUID of the related detection
        method (str): The method of the HTTP request
        type (str): The type of the HTTP request (HTTP or HTTPS)
        host (str): The host of the HTTP request
        status_code (int): The status code of the HTTP request
        path (str): The path of the HTTP request
        full_url (str): The full URL of the HTTP request
        user_agent (str): The user agent of the HTTP request
        referer (str): The referer of the HTTP request
        status_message (str): The status message of the HTTP request
        request_body (str): The request body of the HTTP request
        response_body (str): The response body of the HTTP request
        request_headers (str): The request headers of the HTTP request
        response_headers (str): The response headers of the HTTP request
        http_version (str): The HTTP version of the HTTP request
        file (File): The file transported by the HTTP request
        certificate (Certificate): The certificate used by the HTTP request
        timestamp (datetime): The timestamp of the HTTP request

    Methods:

        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        method: str,
        type: str,
        host: str,
        status_code: int,
        path: str = "",
        full_url: str = None,
        user_agent: str = "Unknown",
        referer: str = None,
        status_message: str = None,
        request_body: str = None,
        response_body: str = None,
        request_headers: List[str] = None,
        response_headers: List[str] = None,
        http_version: str = None,
        certificate: Certificate = None,
        file: ContextFile = None,
        timestamp: datetime.datetime = datetime.datetime.now(),
    ):
        self.related_detection_uuid = related_detection_uuid
        self.full_url = None
        self.user_agent = None
        self.referer = None
        self.status_message = None
        self.request_body = None
        self.response_body = None
        self.request_headers = None
        self.response_headers = None
        self.http_version = None
        self.certificate = None
        self.file = None
        self.timestamp = None

        self.timestamp = timestamp
        mlog = logging_helper.Log("lib.class_helper")

        if method not in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "Unknown (Encrypted)"]:
            raise ValueError("method must be one of GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH")
        self.method = method

        if type not in ["HTTP", "HTTPS"]:
            raise ValueError("type must be one of HTTP, HTTPS")
        self.type = type

        if host == "":
            raise ValueError("host must not be empty")
        self.host = host

        try:
            status_code = int(status_code)
        except:
            if method != "Unknown (Encrypted)":
                raise ValueError("status_code must be an integer")

        self.status_code = status_code

        self.path = None
        if path != None and "/" not in path:
            mlog.warning("HTTP Object __init__: path does not contain any '/'. Path: '" + str(path) + "' Object: " + str(self))
        if path and path[0] != "/":
            self.path = "/" + path
        else:
            self.path = path

        if full_url == None:
            self.full_url = type.lower() + "://" + host + self.path
        else:
            if full_url != type.lower() + "://" + host + self.path:
                mlog.warning("HTTP Object __init__: full_url does not match type, host and/or path. " + str(self))
            self.full_url = full_url

        self.user_agent = user_agent
        self.referer = referer

        self.status_message = status_message  # TODO: Maybe enrich, when empty, with dict values from https://gist.github.com/bl4de/3086cf26081110383631

        self.request_body = request_body
        self.response_body = response_body
        self.request_headers = request_headers
        self.response_headers = response_headers

        if http_version != None and "." not in http_version:
            raise ValueError("http_version must be a valid version number if not None")
        self.http_version = http_version

        # Check if certificate is valid
        if certificate != None:
            if type != "HTTPS":
                raise ValueError("certificate must be None if type is not HTTPS")
            if host not in certificate.subject and host not in certificate.subject_alternative_names:
                mlog = logging_helper.Log("lib.class_helper")
                mlog.warning(
                    "HTTP __init__: Certificate: HTTP.host does not match certificate subject nor subject_alternative_names"
                )
        self.certificate = certificate
        self.file = file

    def __dict__(self):
        try:
            dict_ = {
                "timestamp": self.timestamp,
                "related_detection_uuid": self.related_detection_uuid,
                "method": self.method,
                "type": self.type,
                "host": self.host,
                "status_code": self.status_code,
                "path": self.path,
                "full_url": self.full_url,
                "user_agent": self.user_agent,
                "referer": self.referer,
                "status_message": self.status_message,
                "request_body": self.request_body,
                "response_body": self.response_body if self.response_body != None else "",
                "request_headers": self.request_headers,
                "response_headers": self.response_headers,
                "http_version": self.http_version,
                "certificate": str(self.certificate),
                "file": str(self.file),
            }
        except AttributeError:
            dict_ = {
                "method": self.method,
                "type": self.type,
                "host": self.host,
                "status_code": self.status_code,
            }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ContextFlow:
    """This class provides a single context of type flow for a detection.
       ! Use only if the context of type "DNSQuery", "HTTP" or "Process" is not applicable !

    Attributes:
        related_detection_uuid (str): The related detection unique ID of the context flow
        timestamp (datetime): The timestamp of the flow
        integration (str): The integration from which the flow was received
        source_ip (socket.inet_aton): The source IP of the flow
        source_port (int): The source port of the flow
        destination_ip (socket.inet_aton): The destination IP of the flow
        destination_port (int): The destination port of the flow
        protocol (str): The protocol of the flow
        process_uuid (str): The UID of the process that is responsible for the flow
        process_name (str): The name of the process that is responsible for the flow
        process_id (int): The PID of the process that is responsible for the flow
        data (str): The data of the flow
        bytes_send (int): The bytes send of the flow
        bytes_received (int): The bytes received of the flow
        source_mac (socket.mac): The source MAC of the flow
        destination_mac (str): The destination MAC of the flow
        source_hostname (str): The source hostname of the flow
        destination_hostname (str): The destination hostname of the flow
        category (str): The category of the flow
        sub_category (str): The sub-category of the flow
        flow_direction (str): The flow direction of the flow
        flow_id (int): The flow ID of the flow
        interface (str): The interface of the flow
        network (str): The network of the flow
        network_type (str): The network type of the flow
        flow_source (str): The flow source of the flow
        source_location (Location): The source location of the flow
        destination_location (Location): The destination location of the flow
        http (HTTP): The HTTP context of the flow
        dns_query (DNSQuery): The DNS query context of the flow
        device (ContextDevice): The device that is responsible for the flow
        firewall_action (str): The firewall action of the flow
        firewall_rule_id (int): The firewall rule of the flow
        uuid (uuid.UUID): The UUID of the flow
        detection_relevance (int): The relevance of the flow to the detection (0-100)

    Methods:
        __init__(self, timestamp: datetime.datetime, integration: str, source_ip: socket.inet_aton, source_port: int, destination_ip: socket.inet_aton, destination_port: int, protocol: str, application: str, data: str = None, source_mac: socket.mac = None, destination_mac: str = None, source_hostname: str = None, destination_hostname: str = None, category: str = "Generic Flow", sub_category: str = "Generic HTTP(S) Traffic", flow_direction: str = "L2R", flow_id: int = random.randint(1, 1000000000), interface: str = None, network: str = None, network_type: str = None, flow_source: str = None)
        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        timestamp: datetime.datetime,
        integration: str,
        source_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        source_port: int,
        destination_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        destination_port: int,
        protocol: str,
        process_uuid: uuid.UUID = None,
        process_name: str = None,
        process_id: int = None,
        data: str = None,
        bytes_send: int = None,
        bytes_received: int = None,
        source_mac: str = None,
        destination_mac: str = None,
        source_hostname: str = None,
        destination_hostname: str = None,
        category: str = "Generic Flow",
        sub_category: str = "Generic HTTP(S) Traffic",
        flow_direction: str = None,
        flow_id: int = random.randint(1, 1000000000),
        interface: str = None,
        network: str = None,
        network_type: str = None,
        flow_source: str = None,
        source_location: Location = None,
        destination_location: Location = None,
        application: str = None,
        http: HTTP = None,
        dns_query: DNSQuery = None,
        device: ContextDevice = None,
        firewall_action: str = "Unknown",
        firewall_rule_id: int = None,
        uuid: uuid.UUID = uuid.uuid4(),
        detection_relevance: int = 50,
    ):
        source_ip = cast_to_ipaddress(source_ip)
        destination_ip = cast_to_ipaddress(destination_ip)

        if flow_id < 1 or flow_id > 1000000000:
            raise ValueError("flow_id must be between 1 and 1000000000")

        self.related_detection_uuid = related_detection_uuid

        self.timestamp = timestamp
        self.data = data

        if bytes_send is not None and (type(bytes_send) != int or bytes_send < 0):
            raise ValueError("bytes_send must be an integer greater than 0")
        self.bytes_send = bytes_send

        if bytes_received is not None and (type(bytes_received) != int or bytes_received < 0):
            raise ValueError("bytes_received must be an integer greater than 0")
        self.bytes_received = bytes_received

        self.integration = integration

        self.source_ip = source_ip
        self.source_port = source_port

        self.destination_ip = destination_ip
        self.destination_port = destination_port

        self.protocol = protocol

        self.process_uuid = process_uuid
        self.process_name = process_name
        self.process_id = process_id

        self.source_mac = source_mac
        self.destination_mac = destination_mac

        self.source_hostname = source_hostname
        self.destination_hostname = destination_hostname

        self.category = category
        self.sub_category = sub_category
        self.application = application

        if flow_direction not in ["L2R", "R2L", "L2L", "R2R", None]:
            raise ValueError("flow_direction must be either L2R, L2L, R2L, R2R or None")
        if flow_direction == None:
            if source_ip.is_private and destination_ip.is_private:
                self.flow_direction = "L2L"
            elif source_ip.is_private and not destination_ip.is_private:
                self.flow_direction = "L2R"
            elif not source_ip.is_private and destination_ip.is_private:
                self.flow_direction = "R2L"
            elif not source_ip.is_private and not destination_ip.is_private:
                self.flow_direction = "R2R"
        else:
            self.flow_direction = flow_direction

        self.flow_id = flow_id

        self.interface = interface
        self.network = network
        self.network_type = network_type
        self.flow_source = flow_source

        # Check if location objects are valid if given
        if source_location:
            if not isinstance(source_location, Location):
                raise TypeError("source_location must be of type Location")
            if not source_location.is_valid():
                raise ValueError("source_location is not valid")
        self.source_location = source_location

        if destination_location:
            if not isinstance(destination_location, Location):
                raise TypeError("destination_location must be of type Location")
            if not destination_location.is_valid():
                raise ValueError("destination_location is not valid")
        self.destination_location = destination_location

        # Check if HTTP object is valid if given
        if http:
            if not isinstance(http, HTTP):
                raise TypeError("http must be of type HTTP")
        self.http = http

        # Check if DNSQuery object is valid if given
        if dns_query:
            if not isinstance(dns_query, DNSQuery):
                raise TypeError("dns_query must be of type DNSQuery")
        self.dns_query = dns_query

        # Check if ContextDevice object is valid if given
        if device:
            if not isinstance(device, ContextDevice):
                raise TypeError("device must be of type ContextDevice")
        self.device = device

        self.firewall_action = firewall_action
        if firewall_action == "blocked":
            self.firewall_action = "Deny"

        if (bytes_received is not None and bytes_received == 0) or (bytes_send is not None and bytes_send == 0):
            self.firewall_action = "Deny / Failed Connection"

        if self.firewall_action not in ["Permit", "Deny", "Deny / Failed Connection", "Reject", "Unknown"]:
            raise ValueError("firewall_action must be either Permit, Deny, Reject or Unknown")

        self.firewall_rule_id = firewall_rule_id

        self.uuid = uuid
        self.detection_relevance = handle_percentage(detection_relevance)

    def __dict__(self):
        # Have to overwrite the __dict__ method because of the ipaddress objects

        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "detection relevance": self.detection_relevance,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "integration": self.integration,
            "firewall_action": self.firewall_action,
            "source_ip": str(self.source_ip),
            "source_location": str(self.source_location),
            "source_port": self.source_port,
            "destination_ip": str(self.destination_ip),
            "destination_location": str(self.destination_location),
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "process_uuid": str(self.process_uuid),
            "process_id": self.process_id,
            "process_name": self.process_name,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "source_hostname": self.source_hostname,
            "destination_hostname": self.destination_hostname,
            "category": self.category,
            "sub_category": self.sub_category,
            "flow_direction": self.flow_direction,
            "flow_id": self.flow_id,
            "bytes_send": self.bytes_send,
            "bytes_received": self.bytes_received,
            "interface": self.interface,
            "network": self.network,
            "network_type": self.network_type,
            "flow_source": self.flow_source,
            "application": self.application,
            "http": str(self.http),
            "dns_query": str(self.dns_query),
            "device": str(self.device),
            "firewall_rule_id": self.firewall_rule_id,
            "uuid": str(self.uuid),
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    # ...


class ContextProcess:
    """Process class.

    Attributes:
        process_uuid (str): The UID / EntityID of the process
        timestamp (datetime.datetime): The timestamp of the event
        related_detection_uuid (uuid.UUID): The UUID of the detection this process is related to
        process_name (str): The name of the process
        process_id (int): The ID of the process
        parent_process_name (str): The name of the parent process
        parent_process_id (int): The ID of the parent process
        process_path (str): The path of the process
        process_md5 (str): The MD5 hash of the process
        process_sha1 (str): The SHA1 hash of the process
        process_sha256 (str): The SHA256 hash of the process
        process_command_line (str): The command line of the process
        process_username (str): The username of the process
        process_integrity_level (str): The integrity level of the process
        process_is_elevated_token (bool): True if the process has an elevated token, False if not
        process_token_elevation_type (str): The token elevation type of the process
        process_token_elevation_type_full (str): The token elevation type of the process in full
        process_token_integrity_level (str): The token integrity level of the process
        process_token_integrity_level_full (str): The token integrity level of the process in full
        process_privileges (str): The privileges of the process
        process_owner (str): The owner of the process
        process_group_id (int): The group ID of the process
        process_group_name (str): The group name of the process
        process_logon_guid (str): The logon GUID of the process
        process_logon_id (str): The logon ID of the process
        process_logon_type (str): The logon type of the process
        process_logon_type_full (str): The logon type of the process in full
        process_logon_time (str): The logon time of the process
        process_start_time (str): The start time of the process
        process_parent_start_time (str): The start time of the parent process
        process_current_directory (str): The current directory of the process
        process_image_file_device (str): The image file device of the process
        process_image_file_directory (str): The image file directory of the process
        process_image_file_name (str): The image file name of the process
        process_image_file_path (str): The image file path of the process
        process_dns (DNSQuery): The DNS object of the process
        process_signature (Certificate): The signature's certificate object of the process
        process_http (HTTP): The HTTP object of the process
        process_flow (ContextFlow): The flow object of the process
        process_parent (Process): The parent process object of the process
        process_children (List[Process]): The children processes of the process
        process_environment_variables (List[]): The environment variables of the process
        process_arguments (List[]): The arguments of the process
        process_parent_arguments (List[]): The arguments of the parent process
        process_modules (List[]): The modules of the process
        process_thread (str): The threads of the process
        process_io_text (str): The IO text of the process
        process_io_bytes (str): The IO of the process
        is_complete (bool): Set to True if all available information has been collected, False (default) if not
        detection_relevance (int): The relevance of the process in the detection (0-100)

    Methods:
        __init__(self, process_name: str, process_id: int, parent_process_name: str = "N/A", parent_process_id: int = 0, process_path: str = "", process_md5: str = "", process_sha1: str = "", process_sha256: str = "", process_command_line: str = "", process_username: str = "", process_integrity_level: str = "", process_is_elevated_token: bool = False, process_token_elevation_type: str = "", process_token_elevation_type_full: str = "", process_token_integrity_level: str = "", process_token_integrity_level_full: str = "", process_privileges: str = "", process_owner: str = "", process_group_id: int = "", process_group_name: str = "", process_logon_guid: str = "", process_logon_id: str = "", process_logon_type: str = "", process_logon_type_full: str = "", process_logon_time: str = "", process_start_time: str = "", process_parent_start_time: str = "", process_current_directory: str = "", process_image_file_device: str = "", process_image_file_directory: str = "", process_image_file_name: str = "", process_image_file_path: str = "", process_dns: DNSQuery = None, process_certificate: Certificate = None, process_http: HTTP = None, process_flow: ContextFlow = None, process_parent: ContextProcess = None, process_children: List[ContextProcess] = None, process_environment_variables: List[] = None, process_arguments: List[] = None, process_modules: List[] = None, process_thread: str = "")
        __str__(self)
    """

    # TODO: 1) Change that DNSQuery, HTTP and Certificate are directly inside a ContextFlow object, as they depend on each other [DONE]
    #        1b) Remove them as explicit contexts in Detection and CaseFile [DONE]
    #       2) Make that contexts only refere to itself by UUID [DONE]
    #       3) Create get_context_by_uuid() method in Detection and CaseFile [DONE]
    #       4) Edit the elastic siem integration and building block according to the changes
    #       5) Implement related_detection_uuid in all stand-alone contexts [DONE]
    #       6) Implement relevance scoring in all stand-alone contexts (relevance to the detection) [DONE]

    def __init__(
        self,
        process_uuid: str,
        timestamp: datetime.datetime,
        related_detection_uuid: uuid.UUID,
        process_name: str = "",
        process_id: int = -1,
        parent_process_name: str = "N/A",
        parent_process_id: int = 0,
        parent_process_arguments: List[str] = [],
        process_path: str = "",
        process_md5: str = "",
        process_sha1: str = "",
        process_sha256: str = "",
        process_command_line: str = "",
        process_username: str = "",
        process_integrity_level: str = "",
        process_is_elevated_token: bool = False,
        process_token_elevation_type: str = "",
        process_token_elevation_type_full: str = "",
        process_token_integrity_level: str = "",
        process_token_integrity_level_full: str = "",
        process_privileges: str = "",
        process_owner: str = "",
        process_group_id: int = None,
        process_group_name: str = "",
        process_logon_guid: str = "",
        process_logon_id: str = "",
        process_logon_type: str = "",
        process_logon_type_full: str = "",
        process_logon_time: datetime.datetime = None,
        process_start_time: datetime.datetime = None,
        process_parent_start_time: datetime.datetime = "",
        process_current_directory: str = "",
        process_image_file_device: str = "",
        process_image_file_directory: str = "",
        process_image_file_name: str = "",
        process_image_file_path: str = "",
        process_dns: DNSQuery = None,
        process_signature: Certificate = None,
        process_http: HTTP = None,
        process_flow: ContextFlow = None,
        process_parent: str = None,  # str UUID
        process_children: list = [],  # list of str UUIDs
        process_environment_variables: List[str] = [],
        process_arguments: List[str] = [],
        process_modules: List[str] = [],
        process_thread: str = None,
        created_files: List[ContextFile] = [],
        deleted_files: List[ContextFile] = [],
        modified_files: List[ContextFile] = [],
        created_registry_keys: List[str] = [],
        deleted_registry_keys: List[str] = [],
        modified_registry_keys: List[str] = [],
        process_io_bytes: int = 0,
        process_io_text: str = "",
        is_complete: bool = False,
        detection_relevance: int = 50,
    ):
        mlog = logging_helper.Log("lib.class_helper")

        self.process_uuid = str(process_uuid)
        if process_uuid == None or process_uuid == "":
            raise ValueError("uuid cannot be empty")
        if len(str(process_uuid)) < 36:
            mlog = logging_helper.Log("lib.class_helper")
            mlog.warning("Process Object __init__: given uuid seems too short")

        self.timestamp = timestamp
        self.related_detection_uuid = related_detection_uuid

        self.process_name = process_name

        if process_id < -1:
            raise ValueError("process_id cannot be negative (except -1 for 'unknown')")
        self.process_id = process_id

        self.parent_process_name = parent_process_name

        if parent_process_id != None and parent_process_id < 0:
            raise ValueError("parent_process_id cannot be negative")
        self.parent_process_id = parent_process_id

        self.process_path = process_path

        if process_md5 != None and process_md5 != "" and len(process_md5) != 32:
            raise ValueError("process_md5 must be 32 characters")
        self.process_md5 = process_md5

        if process_sha1 != None and process_sha1 != "" and len(process_sha1) != 40:
            raise ValueError("process_sha1 must be 40 characters")
        self.process_sha1 = process_sha1

        if process_sha256 != None and process_sha256 != "" and len(process_sha256) != 64:
            raise ValueError("process_sha256 must be 64 characters")
        self.process_sha256 = process_sha256

        self.process_command_line = process_command_line
        self.process_username = process_username
        self.process_integrity_level = process_integrity_level
        self.process_is_elevated_token = process_is_elevated_token
        self.process_token_elevation_type = process_token_elevation_type
        self.process_token_elevation_type_full = process_token_elevation_type_full
        self.process_token_integrity_level = process_token_integrity_level
        self.process_token_integrity_level_full = process_token_integrity_level_full
        self.process_privileges = process_privileges
        self.process_owner = process_owner

        if process_group_id != None and process_group_id < 0:
            raise ValueError("process_group_id cannot be negative")
        self.process_group_id = process_group_id

        self.process_group_name = process_group_name
        self.process_logon_guid = process_logon_guid
        self.process_logon_id = process_logon_id
        self.process_logon_type = process_logon_type
        self.process_logon_type_full = process_logon_type_full
        self.process_logon_time = process_logon_time
        self.process_start_time = process_start_time
        self.process_parent_start_time = process_parent_start_time
        self.process_current_directory = process_current_directory
        self.process_image_file_device = process_image_file_device
        self.process_image_file_directory = process_image_file_directory
        self.process_image_file_name = process_image_file_name
        self.process_image_file_path = process_image_file_path
        self.process_dns = process_dns
        self.process_signature = process_signature
        self.process_http = process_http
        self.process_flow = process_flow

        if process_parent is not None and not isinstance(process_parent, str):
            raise TypeError(
                "Process Object __init__: process parent must be of type string to hold the UUID of the process. Got parent process: "
                + str(process_parent)
            )
        self.process_parent = process_parent

        for child in process_children:
            if not isinstance(child, str):
                raise TypeError(
                    "Process Object __init__: all process_children must be of type str to hold the UUID of that child process. Got: "
                    + str(type(child))
                    + "for "
                    + str(child)
                )
        self.process_children = process_children

        self.process_environment_variables = process_environment_variables
        self.process_arguments = process_arguments
        self.parent_process_arguments = parent_process_arguments
        self.process_modules = process_modules
        self.process_thread = process_thread

        self.created_files = created_files
        self.deleted_files = deleted_files
        self.modified_files = modified_files

        self.created_registry_keys = created_registry_keys
        self.deleted_registry_keys = deleted_registry_keys
        self.modified_registry_keys = modified_registry_keys

        if is_complete and process_name == None:
            raise ValueError("process_name cannot be None if is_complete is True")
        if is_complete and process_id == None:
            raise ValueError("process_id cannot be None if is_complete is True")
        if is_complete and process_path == None:
            mlog.warning("Process Object __init__: process_path should not be None if is_complete is True")
        if is_complete and process_md5 == None and process_sha256 == None:
            mlog.warning("Process Object __init__: process_md5 or process_sha256 should not be None if is_complete is True")
        if (
            is_complete and process_command_line == None and False
        ):  # deactivated, as this happens often, even if the rest is complete
            mlog.warning("Process Object __init__: process_command_line should not be None if is_complete is True")
        self.is_complete = is_complete

        self.detection_relevance = handle_percentage(detection_relevance)

        if process_io_text and len(process_io_text) > 0 and process_io_bytes > 0:
            process_io_bytes = len(process_io_text.encode("utf-8"))

        if process_io_bytes and process_io_bytes > THRESHOLD_PROCESS_IO_BYTES:
            mlog.warning(
                "Process Object __init__: process_io_bytes is above threshold of "
                + str(THRESHOLD_PROCESS_IO_BYTES)
                + " bytes. Got: "
                + str(process_io_bytes)
            )
            process_io_bytes = THRESHOLD_PROCESS_IO_BYTES
            process_io_text = process_io_text[:THRESHOLD_PROCESS_IO_BYTES]

        self.process_io_bytes = process_io_bytes
        self.process_io_text = process_io_text

    def __dict__(self):
        _dict = {
            "timestamp": self.timestamp,
            "related_detection_uuid": self.related_detection_uuid,
            "detection_relevance": self.detection_relevance,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process_name": self.parent_process_name,
            "parent_process_id": self.parent_process_id,
            "process_path": self.process_path,
            "process_md5": self.process_md5,
            "process_sha1": self.process_sha1,
            "process_sha256": self.process_sha256,
            "process_command_line": self.process_command_line,
            "process_username": self.process_username,
            "process_integrity_level": self.process_integrity_level,
            "process_is_elevated_token": self.process_is_elevated_token,
            "process_token_elevation_type": self.process_token_elevation_type,
            "process_token_elevation_type_full": self.process_token_elevation_type_full,
            "process_token_integrity_level": self.process_token_integrity_level,
            "process_token_integrity_level_full": self.process_token_integrity_level_full,
            "process_privileges": self.process_privileges,
            "process_owner": self.process_owner,
            "process_group_id": self.process_group_id,
            "process_group_name": self.process_group_name,
            "process_logon_guid": self.process_logon_guid,
            "process_logon_id": self.process_logon_id,
            "process_logon_type": self.process_logon_type,
            "process_logon_type_full": self.process_logon_type_full,
            "process_logon_time": str(self.process_logon_time),
            "process_start_time": str(self.process_start_time),
            "process_parent_start_time": str(self.process_parent_start_time),
            "process_current_directory": self.process_current_directory,
            "process_image_file_device": self.process_image_file_device,
            "process_image_file_directory": self.process_image_file_directory,
            "process_image_file_name": self.process_image_file_name,
            "process_image_file_path": self.process_image_file_path,
            "process_dns": self.process_dns,
            "process_signature": str(self.process_signature),
            "process_http": str(self.process_http),
            "process_flow": str(self.process_flow),
            "process_parent": str(self.process_parent),
            "process_children": str(self.process_children),
            "process_environment_variables": self.process_environment_variables,
            "process_arguments": self.process_arguments,
            "parent_process_arguments": self.parent_process_arguments,
            "process_modules": self.process_modules,
            "process_thread": self.process_thread,
            "created_files": str(self.created_files),
            "deleted_files": str(self.deleted_files),
            "modified_files": str(self.modified_files),
            "created_registry_keys": self.created_registry_keys,
            "deleted_registry_keys": self.deleted_registry_keys,
            "modified_registry_keys": self.modified_registry_keys,
            "is_complete": self.is_complete,
            "uuid": self.process_uuid,
        }
        return _dict

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(del_none_from_dict(self.__dict__())), indent=4, sort_keys=False, default=str)


class ContextLog:
    """The ContextLog class. The most basic context class. Used for storing genric log data like syslog from a SIEM.
       ! Only use this context if no other context is applicable !
       Be aware that either log_source_ip or log_source_device must be set.

    Attrbutes:
        related_detection_uuid (uuid.UUID): The UUID of the detection this log is related to
        timestamp (datetime.datetime): The timestamp of the log
        log_message (str): The message of the log
        log_source_name (str): The source of the log (e.g. Syslog @ Linux Server)
        log_source_ip (ipaddress.IPv4Address or ipaddress.IPv6Address): The IP address of the source of the log
        log_source_device (Device): The device object related to the log
        log_flow (ContextFlow): DEPRECATED Use ContextFlow instead
        log_protocol (str): The protocol of the log
        log_type (str): The type of the log
        log_severity (str): The severity of the log
        log_facility (str): The facility of the log
        log_tags (List[str]): The tags of the log
        log_custom_fields (dict): The custom fields of the log
        detection_relevance (int): The relevance of the log to the detection (0-100)

    Methods:
        __init__(log_message, log_source, log_flow, log_protocol, log_timestamp, log_type, log_severity, log_facility, log_tags, log_custom_fields): Initializes the ContextLog object
        __str__(self): Returns the ContextLog object as a string

    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        timestamp: datetime.datetime,
        log_message: str,
        log_source_name: str,
        log_source_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP,
        log_source_device: ContextDevice = None,
        log_flow: ContextFlow = None,
        log_protocol: str = "",
        log_type: str = "",
        log_severity: str = "",
        log_facility: str = "",
        log_tags: List[str] = None,
        log_custom_fields: dict = None,
        uuid: uuid.UUID = uuid.uuid4(),
        detection_relevance: int = 50,
    ):
        self.related_detection_uuid = related_detection_uuid
        self.timestamp = timestamp
        self.log_message = log_message
        self.log_source_name = log_source_name

        # Check log source IP if set
        if log_source_ip != DEFAULT_IP:
            self.log_source_ip = cast_to_ipaddress(log_source_ip)

        # Check log source device if set
        if log_source_device is not None:
            if not isinstance(log_source_device, ContextDevice):
                raise TypeError(f"Expected type Device for log_source_device, got {type(log_source_device)}")
        self.log_source_device = log_source_device

        # Check if either log_source_device or log_source_ip is set
        if log_source_device is None and log_source_ip == DEFAULT_IP:
            raise ValueError("Either log_source_device or log_source_ip must be set.")

        self.log_flow = log_flow
        self.log_protocol = log_protocol
        self.log_type = log_type
        self.log_severity = log_severity
        self.log_facility = log_facility
        self.log_tags = log_tags
        self.log_custom_fields = log_custom_fields
        self.uuid = uuid
        self.detection_relevance = handle_percentage(detection_relevance)

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": str(self.related_detection_uuid),
            "detection_relevance": self.detection_relevance,
            "timestamp": str(self.timestamp),
            "log_message": self.log_message,
            "log_source_name": self.log_source_name,
            "log_source_ip": str(self.log_source_ip),
            "log_source_device": str(self.log_source_device),
            "log_flow": self.log_flow,
            "log_protocol": self.log_protocol,
            "log_type": self.log_type,
            "log_severity": self.log_severity,
            "log_facility": self.log_facility,
            "log_tags": self.log_tags,
            "log_custom_fields": self.log_custom_fields,
            "uuid": str(self.uuid),
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ContextRegistry:
    """The ContextRegistry class. Used for storing registry data.

    Attributes:
        action (str): The action of the registry event
        registry_key (str): The registry key
        registry_value (str): The registry value
        registry_data (str): The registry data
        registry_data_type (str): The registry data type
        registry_hive (str): The registry hive
        registry_path (str): The registry path
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        timestamp: datetime.datetime,
        action: str,
        registry_key: str,
        registry_value: str,
        registry_data: str = None,
        registry_data_type: str = None,
        registry_hive: str = None,
        registry_path: str = None,
        process_name: str = None,
        process_id: int = None,
        process_uuid: str = None,
    ):
        self.related_detection_uuid = related_detection_uuid
        self.timestamp = timestamp
        self.action = action
        self.registry_key = registry_key
        self.registry_value = registry_value
        self.registry_data = registry_data
        self.registry_data_type = registry_data_type
        self.registry_hive = registry_hive
        self.registry_path = registry_path
        self.process_name = process_name
        self.process_id = process_id
        self.process_uuid = process_uuid

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": str(self.related_detection_uuid),
            "timestamp": str(self.timestamp),
            "action": self.action,
            "registry_key": self.registry_key,
            "registry_value": self.registry_value,
            "registry_data": self.registry_data,
            "registry_data_type": self.registry_data_type,
            "registry_hive": self.registry_hive,
            "registry_path": self.registry_path,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "process_uuid": self.process_uuid,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ThreatIntel:
    """Detection by an idividual threat intel engine (e.g. Kaspersky, Avast, Microsoft, etc.).
       ! This class is not a stand-alone context. !
       Use it in ContextThreatIntel context to store multiple threat intel engines.

    Attributes:
        engine (str): The name of the detection engine
        is_known (bool): If the indicator is known by the detection engine
        is_hit (bool): If the detection engine hit on the indicator
        hit_type (str): The type of the hit (e.g. malicious, suspicious, etc.)
        threat_name (str): The name of the threat (if available)
        confidence (int): The confidence of the detection engine (if available)
        engine_version (str): The version of the detection engine
        engine_update (datetime): The last update of the detection engine
        method (str): The method of the detection engine (e.g. signature, heuristics, etc.)
        is_related_indicator (bool): If the the object is part of a related indicator or directly related to the indicator of the ContextThreatIntel object
        related_indicator_name (str): The name of the related indicator (if is_related_indicator is True)
    """

    def __init__(
        self,
        time_requested: datetime.datetime,
        engine: str,
        is_known: bool,
        is_hit: bool = False,
        hit_type: str = "",
        threat_name: str = "",
        confidence: int = "",
        engine_version: str = "",
        engine_last_updated: datetime = None,
        detection_last_seen: datetime.datetime = None,
        detection_last_update: datetime.datetime = None,
        method: str = "",
        is_related_indicator: bool = False,
        related_indicator_name: str = "",
    ):
        self.time_requested = time_requested

        if not is_known and is_hit:
            raise ValueError("is_hit must be False if is_known is False")
        if not is_known and hit_type != "":
            raise ValueError("hit_type must be empty if is_known is False")
        if not is_known and threat_name != "":
            raise ValueError("threat_name must be empty if is_known is False")
        if not is_known and confidence != "":
            raise ValueError("confidence must be empty if is_known is False")
        self.is_known = is_known

        hit_type = hit_type.lower()
        if is_hit and hit_type not in ["malicious", "suspicious", "unknown"]:
            raise ValueError("hit_type must be one of malicious, suspicious or unknown if is_hit is True")
        self.is_hit = is_hit

        self.hit_type = hit_type
        self.threat_name = threat_name
        self.confidence = confidence
        self.engine = engine
        self.engine_version = engine_version
        self.engine_update = engine_last_updated
        self.detection_last_seen = detection_last_seen
        self.detection_last_update = detection_last_update
        self.method = method
        self.is_related_indicator = is_related_indicator
        self.related_indicator_name = related_indicator_name

    def __dict__(self):
        _dict = {
            "time_requested": str(self.time_requested),
            "engine": self.engine,
            "is_related_indicator": self.is_related_indicator,
            "related_indicator_name": self.related_indicator_name,
            "is_known": self.is_known,
            "is_hit": self.is_hit,
            "hit_type": self.hit_type,
            "threat_name": self.threat_name,
            "confidence": self.confidence,
            "engine_version": self.engine_version,
            "engine_update": str(self.engine_update),
            "detection_last_seen": str(self.detection_last_seen),
            "detection_last_update": str(self.detection_last_update),
            "method": self.method,
        }
        return _dict

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class Whois:
    """Whois information of a domain.
    ! This class is not a stand-alone context. Use it in ContextThreatIntel context to store the whois information.

    Attributes:
        Domain_Name:
        Registry_Domain_ID:
        Registrar_WHOIS_Server:
        Registrar_URL:
        Updated_Date:
        Creation_Date:
        Registry_Expiry_Date:
        Registrar:
        Registrar_Abuse_Contact_Email:
        Registrar_Abuse_Contact_Phone:
        Domain_Status:
        Registry_Registrant_ID:
        Registrant_Name:
        Registrant_Organization:
        Registrant_Street:
        Registrant_Street:
        Registrant_Street:
        Registrant_City:
        Registrant_State/Province:
        Registrant_Postal_Code:
        Registrant_Country:
        Registrant_Phone:
        Registrant_Phone_Ext:
        Registrant_Fax:
        Registrant_Fax_Ext:
        Registrant_Email:
        Registry_Admin_ID:
        Admin_Name:
        Admin_Organization:
        Admin_Street:
        Admin_Street:
        Admin_Street:
        Admin_City:
        Admin_State/Province:
        Admin_Postal_Code:
        Admin_Country:
        Admin_Phone:
        Admin_Phone_Ext:
        Admin_Fax:
        Admin_Fax_Ext:
        Admin_Email:
        Registry_Tech_ID:
        Tech_Name:
        Tech_Organization:
        Tech_Street:
        Tech_Street:
        Tech_Street:
        Tech_City:
        Tech_State/Province:
        Tech_Postal_Code:
        Tech_Country:
        Tech_Phone:
        Tech_Phone_Ext:
        Tech_Fax:
        Tech_Fax_Ext:
        Tech_Email:
        Name_Server:
        Name_Server:
        DNSSEC:"""

    def __init__(
        self,
        domain_name,
        registry_domain_id,
        registrar_whois_server,
        registrar_url,
        updated_date,
        creation_date,
        registry_expiry_date,
        registrar,
        registrar_abuse_contact_email,
        registrar_abuse_contact_phone,
        domain_status,
        registry_registrant_id,
        registrant_name,
        registrant_organization,
        registrant_street,
        registrant_city,
        registrant_state_province,
        registrant_postal_code,
        registrant_country,
        registrant_phone,
        registrant_phone_ext,
        registrant_fax,
        registrant_fax_ext,
        registrant_email,
        registry_admin_id,
        admin_name,
        admin_organization,
        admin_street,
        admin_city,
        admin_state_province,
        admin_postal_code,
        admin_country,
        admin_phone,
        admin_phone_ext,
        admin_fax,
        admin_fax_ext,
        admin_email,
        registry_tech_id,
        tech_name,
        tech_organization,
        tech_street,
        tech_city,
        tech_state_province,
        tech_postal_code,
        tech_country,
        tech_phone,
        tech_phone_ext,
        tech_fax,
        tech_fax_ext,
        tech_email,
        name_server1,
        name_server2,
        dnssec,
    ):
        self.domain_name = domain_name
        self.registry_domain_id = registry_domain_id
        self.registrar_whois_server = registrar_whois_server
        self.registrar_url = registrar_url
        self.updated_date = updated_date
        self.creation_date = creation_date
        self.registry_expiry_date = registry_expiry_date
        self.registrar = registrar
        self.registrar_abuse_contact_email = registrar_abuse_contact_email
        self.registrar_abuse_contact_phone = registrar_abuse_contact_phone
        self.domain_status = domain_status
        self.registry_registrant_id = registry_registrant_id
        self.registrant_name = registrant_name
        self.registrant_organization = registrant_organization
        self.registrant_street = registrant_street
        self.registrant_city = registrant_city
        self.registrant_state_province = registrant_state_province
        self.registrant_postal_code = registrant_postal_code
        self.registrant_country = registrant_country
        self.registrant_phone = registrant_phone
        self.registrant_phone_ext = registrant_phone_ext
        self.registrant_fax = registrant_fax
        self.registrant_fax_ext = registrant_fax_ext
        self.registrant_email = registrant_email
        self.registry_admin_id = registry_admin_id
        self.admin_name = admin_name
        self.admin_organization = admin_organization
        self.admin_street = admin_street
        self.admin_city = admin_city
        self.admin_state_province = admin_state_province
        self.admin_postal_code = admin_postal_code
        self.admin_country = admin_country
        self.admin_phone = admin_phone
        self.admin_phone_ext = admin_phone_ext
        self.admin_fax = admin_fax
        self.admin_fax_ext = admin_fax_ext
        self.admin_email = admin_email
        self.registry_tech_id = registry_tech_id
        self.tech_name = tech_name
        self.tech_organization = tech_organization
        self.tech_street = tech_street
        self.tech_city = tech_city
        self.tech_state_province = tech_state_province
        self.tech_postal_code = tech_postal_code
        self.tech_country = tech_country
        self.tech_phone = tech_phone
        self.tech_phone_ext = tech_phone_ext
        self.tech_fax = tech_fax
        self.tech_fax_ext = tech_fax_ext
        self.tech_email = tech_email
        self.name_server1 = name_server1
        self.name_server2 = name_server2
        self.dnssec = dnssec

    def __dict__(self):
        """Returns the object as a dictionary."""
        return {
            "domain_name": self.domain_name,
            "registry_domain_id": self.registry_domain_id,
            "registrar_whois_server": self.registrar_whois_server,
            "registrar_url": self.registrar_url,
            "updated_date": self.updated_date,
            "creation_date": self.creation_date,
            "registry_expiry_date": self.registry_expiry_date,
            "registrar": self.registrar,
            "registrar_abuse_contact_email": self.registrar_abuse_contact_email,
            "registrar_abuse_contact_phone": self.registrar_abuse_contact_phone,
            "domain_status": self.domain_status,
            "registry_registrant_id": self.registry_registrant_id,
            "registrant_name": self.registrant_name,
            "registrant_organization": self.registrant_organization,
            "registrant_street": self.registrant_street,
            "registrant_city": self.registrant_city,
            "registrant_state_province": self.registrant_state_province,
            "registrant_postal_code": self.registrant_postal_code,
            "registrant_country": self.registrant_country,
            "registrant_phone": self.registrant_phone,
            "registrant_phone_ext": self.registrant_phone_ext,
            "registrant_fax": self.registrant_fax,
            "registrant_fax_ext": self.registrant_fax_ext,
            "registrant_email": self.registrant_email,
            "registry_admin_id": self.registry_admin_id,
            "admin_name": self.admin_name,
            "admin_organization": self.admin_organization,
            "admin_street": self.admin_street,
            "admin_city": self.admin_city,
            "admin_state_province": self.admin_state_province,
            "admin_postal_code": self.admin_postal_code,
            "admin_country": self.admin_country,
            "admin_phone": self.admin_phone,
            "admin_phone_ext": self.admin_phone_ext,
            "admin_fax": self.admin_fax,
            "admin_fax_ext": self.admin_fax_ext,
            "admin_email": self.admin_email,
            "registry_tech_id": self.registry_tech_id,
            "tech_name": self.tech_name,
            "tech_organization": self.tech_organization,
            "tech_street": self.tech_street,
            "tech_city": self.tech_city,
            "tech_state_province": self.tech_state_province,
            "tech_postal_code": self.tech_postal_code,
            "tech_country": self.tech_country,
            "tech_phone": self.tech_phone,
            "tech_phone_ext": self.tech_phone_ext,
            "tech_fax": self.tech_fax,
            "tech_fax_ext": self.tech_fax_ext,
            "tech_email": self.tech_email,
            "name_server1": self.name_server1,
            "name_server2": self.name_server2,
            "dnssec": self.dnssec,
        }


def __str__(self):
    """Returns the string representation of the object."""
    return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ContextThreatIntel:
    """DetectionThreatIntel class. This class is used for storing threat intel (e.g. VirusTotal, AlienVault OTX, etc.).
    The risk score can generally be calculated as score_hit / score_known.

    Attributes:
        type (type): The type of the indicator
        indicator(socket.intet_aton | HTTP | DNSQuery | ContextProcess ) The indicator
        source (str): The integration source of the indicator
        timestamp (datetime): The timestamp of the lookup
        threat_intel_detections (List[ThreatIntel]): The threat intel detections of the indicator
        score_hit (int): The hits on the particular indicator
        score_total (int): The total number of engines that were queried
        score_hit_sus (int): The number of suspicious hits on the indicator
        score_hit_mal (int): The number of malicious hits on the indicator
        score_known (int): The number of engines that know the indicator
        score_unknown (int): The number of engines that don't know the indicator
        related_detection_uuid (uuid.UUID): The UUID of the related detection
        detection_relevance (int): The relevance of the threat intel to the detection (0-100)
        tags (List[str]): The tags of the threat intel
        last_analyzed (datetime): The last time the indicator was analyzed
        AS_owner (str): The owner of the AS (if available)
        AS_number (str): The number of the AS (if available)
        AS_IP_Range (str): The IP range of the AS (if available)
        related_cert (Certificate): The related certificate (if available)
        related_domains (List[ThreatIntel]): Related domains to an IP or File indicator (if available)
        related_files (List[ThreatIntel]): Related files to an IP or Domain indicator (if available)
        related_ips (List[ThreatIntel]): Related IPs to a Domain or File indicator (if available)
        related_urls (List[ThreatIntel]): Related URLs to an IP, Domain or File indicator (if available)
        categories (List[List[str]]): The categories of the indicator (if available). Nested List contains the engine name [0] and the category [1]

        whois (Whois): The whois of the indicator (if available)

    Methods:
        __init__(type, indicator, source, timestamp, threat_intel_detections, score_hit, score_total): Initializes the ContextThreatIntel object
        __str__(self): Returns the ContextThreatIntel object as a string
    """

    def __init__(
        self,
        type: type,
        indicator: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, HTTP, DNSQuery, ContextFile, ContextProcess],
        source: str,
        timestamp: datetime.datetime,
        threat_intel_detections: List[ThreatIntel],
        score_hit: int = None,
        score_total: int = None,
        score_hit_sus: int = None,
        score_hit_mal: int = None,
        score_known: int = None,
        score_unknown: int = None,
        related_detection_uuid: uuid.UUID = None,
        uuid: uuid.UUID = uuid.uuid4(),
        detection_relevance: int = 50,
        tags: List[str] = [],
        last_analyzed: datetime.datetime = None,
        AS_owner: str = None,
        AS_number: str = None,
        AS_IP_Range: str = None,
        related_cert: Certificate = None,
        whois: Whois = None,
        related_domains: List[ThreatIntel] = [],
        related_files: List[ThreatIntel] = [],
        related_ips: List[ThreatIntel] = [],
        related_urls: List[ThreatIntel] = [],
        categories: List[List[str]] = [],
        links: List[str] = [],
    ):
        if type not in [ipaddress.IPv4Address, ipaddress.IPv6Address, HTTP, DNSQuery, ContextFile, ContextProcess]:
            raise ValueError("type must be one of IPv4Address, IPv6Address, HTTP, DNSQuery, ContextFile or ContextProcess")
        self.type = type

        # if not isinstance(indicator, type):
        #    raise ValueError("indicator must be of the given 'type'")

        self.indicator = indicator
        self.source = source
        self.timestamp = timestamp
        self.threat_intel_detections = threat_intel_detections

        if score_hit is not None and score_total is not None and score_hit_sus is not None and score_hit_mal is not None:
            if score_total < 0:
                raise ValueError("score_total must be greater or equal to 0 if not None")
            if score_hit < 0:
                raise ValueError("score_hit must be greater or equal to 0 if not None")
            if score_hit > score_total:
                raise ValueError("score_hit must be smaller or equal to score_total if not None")
            self.score_hit = score_hit
            self.score_total = score_total
        else:
            # Calculate implicit score using threat_intel_detections
            self.score_total = len(threat_intel_detections)
            self.score_hit = 0
            if score_hit_sus is None:
                calc_sus = True
                self.score_hit_sus = 0
            if score_hit_mal is None:
                calc_mal = True
                self.score_hit_mal = 0

            for detection in threat_intel_detections:
                if detection.is_hit:
                    self.score_hit += 1
                    if detection.hit_type == "suspicious" and calc_sus:
                        self.score_hit_sus = self.score_hit_sus + 1
                    if detection.hit_type == "malicious" and calc_mal:
                        self.score_hit_mal = self.score_hit_mal + 1

        if score_hit_sus is not None:
            if score_hit_sus < 0:
                raise ValueError("score_hit_sus must be greater or equal to 0 if not None")
            if score_hit_sus > self.score_hit:
                raise ValueError("score_hit_sus must be smaller or equal to score_hit if not None")
            self.score_hit_sus = score_hit_sus

        if score_hit_mal is not None:
            if score_hit_mal < 0:
                raise ValueError("score_hit_mal must be greater or equal to 0 if not None")
            if score_hit_mal > self.score_hit:
                raise ValueError("score_hit_mal must be smaller or equal to score_hit if not None")
            self.score_hit_mal = score_hit_mal

        if score_known is not None:
            if score_known < 0:
                raise ValueError("score_known must be greater or equal to 0 if not None")
            if score_known > self.score_total:
                raise ValueError("score_known must be smaller or equal to score_total if not None")
            self.score_known = score_known
        else:
            self.score_known = 0
            for detection in threat_intel_detections:
                if detection.is_known:
                    self.score_known += 1

        if score_unknown is not None:
            if score_unknown < 0:
                raise ValueError("score_unknown must be greater or equal to 0 if not None")
            if score_unknown > self.score_total:
                raise ValueError("score_unknown must be smaller or equal to score_total if not None")
            if score_unknown != None and score_known != None:
                if score_unknown != self.score_total - self.score_known:
                    raise ValueError("score_unknown must be equal to score_total - score_known if not None")
            self.score_unknown = score_unknown
        else:
            if self.score_known == None or self.score_total == None:  # Should not happen, as set above
                mlog = logging_helper.Log("lib.class_helper")
                mlog.error(
                    "Class ThreatIntel __init__: implicit calculation of score_unknown: score_unknown is not set and score_known or score_total is None. score_unknown cannot be calculated. You shouldn't see this message. Please case this issue."
                )
                raise SystemError(
                    "Class ThreatIntel __init__: implicit calculation of score_unknown: score_unknown is not set and score_known or score_total is None. score_unknown cannot be calculated. You shouldn't see this message. Please case this issue."
                )
            else:
                self.score_unknown = self.score_total - self.score_known

        self.related_detection_uuid = related_detection_uuid
        self.uuid = uuid
        self.detection_relevance = handle_percentage(detection_relevance)
        self.tags = tags
        self.last_analyzed = last_analyzed
        self.AS_owner = AS_owner
        self.AS_number = AS_number
        self.AS_IP_Range = AS_IP_Range
        self.related_cert = related_cert
        self.whois = whois
        self.related_ips = related_ips
        self.related_domains = related_domains
        self.related_files = related_files
        self.related_urls = related_urls

        self.categories = []
        if categories:
            if isinstance(categories, list) and len(categories) == 2:
                self.categories = categories
            else:
                raise ValueError("categories must be a list of two elements (engine and category)")

        self.links = links

    def __dict__(self):
        """Returns the object as a dictionary."""
        dict_ = {
            "type": self.type,
            "indicator": self.indicator,
            "source": self.source,
            "timestamp": self.timestamp,
            "threat_intel_detections": self.threat_intel_detections,
            "score_hit": self.score_hit,
            "score_total": self.score_total,
            "score_hit_sus": self.score_hit_sus,
            "score_hit_mal": self.score_hit_mal,
            "score_known": self.score_known,
            "score_unknown": self.score_unknown,
            "related_detection_uuid": self.related_detection_uuid,
            "detection_relevance": self.detection_relevance,
            "tags": self.tags,
            "last_analyzed": self.last_analyzed,
            "AS_owner": self.AS_owner,
            "AS_number": self.AS_number,
            "AS_IP_Range": self.AS_IP_Range,
            "related_cert": str(self.related_cert),
            "related_ips": str(self.related_ips),
            "related_domains": str(self.related_domains),
            "related_files": str(self.related_files),
            "related_urls": str(self.related_urls),
            "whois": str(self.whois),
            "uuid": self.uuid,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        clean_dict = del_none_from_dict(self.__dict__())
        return json.dumps(clean_dict, indent=4, sort_keys=False, default=str)


class Detection:
    """Detection class. This class is used for storing detections.

    Attributes:
        vendor_id (str): The vendor specific ID of the detection, note that for unique identification, the 'uuid' of the detection is used
        name (str): The name of the detection
        rules (List[Rule]): The rules that triggered the detection
        timestamp (datetime): The timestamp of the detection
        description (str): The description of the detection
        tags (List[str]): The tags of the detection
        raw (str): The raw detection
        host_name (str): The source host of the detection
        host_ip (ipaddress.IPV4Address): The IP of the host of the detection
        severity (int): The severity of the detection
        log (ContextLog): The log object of the detection if applicable
        process (Process): The process related to the detection
        flow (ContextFlow): The flow related to the detection (source and destination IP and port etc.)
        threat_intel (ContextThreatIntel): The threat intel directly related to the detection
        location (Location): The location of the detection (e.g. country)
        device (Device): The device that triggered the detection
        user (Person): The user that triggered the detection
        file (File): A file related to the detection
        http_request (HTTP): A HTTP request related to the detection
        dns_request (DNS): A DNS request related to the detection
        certificate (Certificate): A certificate related to the detection
        registry (Registry): A registry related to the detection
        log_source (str): The source of the log (e.g. Windows Event Log, Sysmon, etc.)
        url (str): The URL of the detection
        uuid (str): The universal unique ID of the detection (UUID v4 - random if not set)

    Methods:
        __init__(self, id: str, name: str, rules: List[Rule], description: str = None, tags: List[str] = None, raw: str = None, timestamp: datetime = None, source: str = None, source_ip: socket.inet_aton = None, source_port: int = None, destination: str = None, destination_ip: datetime = None, destination_port: int = None, protocol: str = None, severity: int = None, process: ContextProcess = None)
        __str__(self)
        get_context_by_uuid(self, uuid: str) -> Context or None: Returns the context object with the given UUID
    """

    def __init__(
        self,
        vendor_id: str,
        name: str,
        rules: List[Rule],
        timestamp: datetime,
        description: str = None,
        tags: List[str] = None,
        raw: str = None,
        host_name: str = None,
        host_ip: ipaddress.IPv4Address = None,
        severity: int = None,
        # Context for every type of context
        log: ContextLog = None,
        process: ContextProcess = None,
        flow: ContextFlow = None,
        threat_intel: ContextThreatIntel = None,
        location: Location = None,
        device: ContextDevice = None,
        user: Person = None,
        file: ContextFile = None,
        registry: ContextRegistry = None,
        log_source: str = None,
        url: str = None,
        uuid: uuid.UUID = uuid.uuid4(),
    ):
        self.vendor_id = vendor_id
        self.name = name
        self.description = description

        self.timestamp = timestamp
        if type(timestamp) == str:
            # '2023-06-29T17:33:44.091Z'
            self.timestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")

        self.source = host_name

        self.severity = severity
        self.tags = tags
        self.raw = raw
        self.rules = rules
        self.indicators = {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": [],
            "email": [],
            "countries": [],
            "registry": [],
            "other": [],
        }

        if host_ip != None:
            host_ip = cast_to_ipaddress(host_ip)
            self.indicators["ip"].append(host_ip)
        self.host_ip = host_ip

        # Context for every type of context with checks
        if log != None:
            if not isinstance(log, ContextLog):
                raise TypeError("log must be of type ContextLog")
            if log.log_flow:
                self.indicators["ip"].append(log.log_flow.source_ip)
                self.indicators["ip"].append(log.log_flow.destination_ip)
        self.log = log

        if process != None:
            if not isinstance(process, ContextProcess):
                raise TypeError("process must be of type ContextProcess")
            if process.process_flow:
                self.indicators["ip"].append(process.process_flow.source_ip)
                self.indicators["ip"].append(process.process_flow.destination_ip)
            if process.process_md5:
                self.indicators["hash"].append(process.process_md5)
            if process.process_sha1:
                self.indicators["hash"].append(process.process_sha1)
            if process.process_sha256:
                self.indicators["hash"].append(process.process_sha256)
        self.process = process

        if flow != None:
            if not isinstance(flow, ContextFlow):
                raise TypeError("flow must be of type ContextFlow")
            self.indicators["ip"].append(flow.source_ip)
            self.indicators["ip"].append(flow.destination_ip)
        self.flow = flow

        if threat_intel != None:
            if not isinstance(threat_intel, ContextThreatIntel):
                raise TypeError("threat_intel must be of type ContextThreatIntel")
        self.threat_intel = threat_intel

        if location != None:
            if not isinstance(location, Location):
                raise TypeError("location must be of type Location")
            if location.country:
                self.indicators["countries"].append(location.country)
        self.location = location

        if device != None:
            if not isinstance(device, ContextDevice):
                raise TypeError("device must be of type Device")
        self.device = device

        if user != None:
            if not isinstance(user, Person):
                raise TypeError("user must be of type Person")
        self.user = user

        if file == None and flow != None and dict_get(flow, "http.file") != None:
            file = flow.http.file

        if file != None:
            if not isinstance(file, ContextFile):
                raise TypeError("file must be of type ContextFile")
            self.indicators["other"].append(file.file_name)
            if file.file_md5:
                self.indicators["hash"].append(file.file_md5)
            if file.file_sha1:
                self.indicators["hash"].append(file.file_sha1)
            if file.file_sha256:
                self.indicators["hash"].append(file.file_sha256)
        self.file = file

        http_request = None
        if flow != None and flow.http:
            http_request = flow.http
        self.http_request = http_request

        dns_request = None
        if flow != None and flow.dns_query:
            dns_request = flow.dns_query
        self.dns_request = dns_request

        certificate = None
        if flow != None and flow.http != None and flow.http.certificate:
            certificate = flow.http.certificate
        self.certificate = certificate

        if http_request != None:
            if not isinstance(http_request, HTTP):
                raise TypeError("http_request must be of type HTTP")
            self.indicators["domain"].append(http_request.host)
            self.indicators["url"].append(http_request.full_url)
            if http_request.request_body:
                self.indicators["other"].append(http_request.request_body)
            if http_request.file:
                self.indicators["other"].append(http_request.file.file_name)
                if http_request.file.file_md5:
                    self.indicators["hash"].append(http_request.file.file_md5)
                if http_request.file.file_sha1:
                    self.indicators["hash"].append(http_request.file.file_sha1)
                if http_request.file.file_sha256:
                    self.indicators["hash"].append(http_request.file.file_sha256)
        self.http_request = http_request

        if dns_request != None:
            if not isinstance(dns_request, DNSQuery):
                raise TypeError("dns_request must be of type DNSQuery")
            self.indicators["domain"].append(dns_request.query)
            if dns_request.query_response and cast_to_ipaddress(dns_request.query_response):
                self.indicators["ip"].append(dns_request.query_response)

        if certificate != None:
            if not isinstance(certificate, Certificate):
                raise TypeError("certificate must be of type Certificate")
            self.indicators["domain"].append(certificate.subject)
            if certificate.subject_alternative_names is not None and len(certificate.subject_alternative_names) > 0:
                for san in certificate.subject_alternative_names:
                    self.indicators["domain"].append(san)

        if registry != None:
            if not isinstance(registry, ContextRegistry):
                raise TypeError("registry must be of type ContextRegistry")
            self.indicators["registry"].append(registry.registry_key)
        self.registry = registry
        self.log_source = log_source
        self.url = url

        self.uuid = uuid
        self.ticket: pyotrs.Ticket = None

        # Remove '*.' from domain indicators and replace with empty
        for domain in self.indicators["domain"]:
            if domain.startswith("*."):
                mlog = logging_helper.Log("lib.class_helper")
                mlog.debug(f"Removing '*.' from domain indicator: {domain}")
                self.indicators["domain"].remove(domain)
                self.indicators["domain"].append(domain[2:])

        # Remove duplicates
        remove_duplicates_from_dict(self.indicators)

    def __dict__(self):
        """Returns the dictionary representation of the object."""
        dict_ = {
            "id": self.vendor_id,
            "name": self.name,
            "description": self.description,
            "timestamp": self.timestamp,
            "host_name": self.source,
            "host_ip": self.host_ip,
            "severity": self.severity,
            "tags": self.tags,
            "raw": self.raw,
            "rules": self.rules,
            "log": str(self.log),
            "process": str(self.process),
            "flow": str(self.flow),
            "threat_intel": str(self.threat_intel),
            "location": str(self.location),
            "device": str(self.device),
            "user": str(self.user),
            "file": str(self.file),
            "registry": str(self.registry),
            "log_source": self.log_source,
            "url": self.url,
            "uuid": self.uuid,
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    def get_context_by_uuid(self, uuid):
        """Returns the context object by uuid.

        Args:
            uuid (str): The uuid of the context object

        Returns:
            Any: The context object
        """
        if self.log.uuid == uuid:
            return self.log

        if self.process.uuid == uuid:
            return self.process

        if self.flow.uuid == uuid:
            return self.flow

        if self.threat_intel.uuid == uuid:
            return self.threat_intel

        if self.location.uuid == uuid:
            return self.location

        if self.device.uuid == uuid:
            return self.device

        if self.user.uuid == uuid:
            return self.user

        if self.file.uuid == uuid:
            return self.file

        return None

    def check_against_whitelist(self) -> bool:
        """Checks the case against the whitelist.

        Args:
            cache_integration_name (str): The name of the cache integration

        Returns:
            bool: True if the case is whitelisted, False otherwise
        """
        from lib.generic_helper import get_from_cache

        mlog = logging_helper.Log("lib.class_helper")
        detection = self

        wl_ips = get_from_cache("global_whitelist_ips", "LIST")
        wl_ips = wl_ips if wl_ips is not None else []
        wl_ips = list(set(wl_ips))  # Remove duplicates
        wl_ips = [ip for ip in wl_ips if ip != ""]  # Remove empty entries
        mlog.debug(f"Found {len(wl_ips)} IPs in global whitelist.")

        for ip in detection.indicators["ip"]:
            if ip in wl_ips:
                mlog.info(f"IP '{ip}' is whitelisted.")
                return True

        wl_domains = get_from_cache("global_whitelist_domains", "LIST")
        wl_domains = wl_domains if wl_domains is not None else []
        wl_domains = list(set(wl_domains))  # Remove duplicates
        wl_domains = [domain for domain in wl_domains if domain != ""]  # Remove empty entries
        mlog.debug(f"Found {len(wl_domains)} domains in global whitelist.")

        for domain in detection.indicators["domain"]:
            if domain in wl_domains:
                mlog.info(f"Domain '{domain}' is whitelisted.")
                return True

        wl_hashes = get_from_cache("global_whitelist_hashes", "LIST")
        wl_hashes = wl_hashes if wl_hashes is not None else []
        wl_hashes = list(set(wl_hashes))  # Remove duplicates
        wl_hashes = [hash_ for hash_ in wl_hashes if hash_ != ""]  # Remove empty entries
        mlog.debug(f"Found {len(wl_hashes)} hashes in global whitelist.")

        for hash_ in detection.indicators["hash"]:
            if hash_ in wl_hashes:
                mlog.info(f"Hash '{hash_}' is whitelisted.")
                return True

        wl_urls = get_from_cache("global_whitelist_urls", "LIST")
        wl_urls = wl_urls if wl_urls is not None else []
        wl_urls = list(set(wl_urls))  # Remove duplicates
        wl_urls = [url for url in wl_urls if url != ""]  # Remove empty entries
        mlog.debug(f"Found {len(wl_urls)} URLs in global whitelist.")

        for url in detection.indicators["url"]:
            if url in wl_urls:
                mlog.info(f"URL '{url}' is whitelisted.")
                return True

        wl_emails = get_from_cache("global_whitelist_emails", "LIST")
        wl_emails = wl_emails if wl_emails is not None else []
        wl_emails = list(set(wl_emails))  # Remove duplicates
        wl_emails = [email for email in wl_emails if email != ""]  # Remove empty entries
        mlog.debug(f"Found {len(wl_emails)} emails in global whitelist.")

        for email in detection.indicators["email"]:
            if email in wl_emails:
                mlog.info(f"Email '{email}' is whitelisted.")
                return True

        mlog.debug("Detection is not whitelisted in the global whitelist.")
        return False


class AuditLog:
    """The "AuditLog" class serves as a centralized mechanism to capture and document the actions performed by ZSOAR, particularly by its "Playbooks," that impact the detection cases.
       Generally a planned action is declared first as a new AuditLog, pushed to the audit trail, and then executed. The relevant AuditLog is then updated with the result of the action.

    Args:
        playbook (str): The name of the playbook
        stage (int): The stage of the playbook
        title (str): The title of the audit log entry. This is the main description of the action (to be) performed.
        description (str, optional): The description of the audit log entry. Defaults to "".
        start_time (datetime, optional): The start time of the audit log entry. Defaults to datetime.datetime.now().
        related_ticket_number (str, optional): The ticket number related to the audit log entry. Defaults to "".
        is_ticket_related (bool, optional): Indicates whether the audit log entry is related to a ticket. Defaults to False.
        result_had_warnings (bool, optional): Indicates whether the audit log entry had warnings. Defaults to False.
        result_had_errors (bool, optional): Indicates whether the audit log entry had errors. Defaults to False.
        result_request_retry (bool, optional): Indicates whether the action should be retried. Defaults to False.
        result_message (str, optional): The result message of the action performed. Defaults to "".
        result_data (dict, optional): Additional relevant data of the action performed. Defaults to {}.
        result_in_ticket (bool, optional): Indicates whether the result has been added to the ticket. Defaults to False.
        result_time (datetime, optional): The time of the result. Defaults to None.
        stage_done (bool, optional): Indicates whether the action of this stage has been completed (in any way). Defaults to False.
        playbook_done (bool, optional): Indicates whether the playbook has been completed. Defaults to False.

    """

    def __init__(
        self,
        playbook: str,
        stage: int,
        title: str,
        description: str = "",
        start_time: datetime = datetime.datetime.now(),
        is_ticket_related: bool = False,
        result_had_warnings: bool = False,
        result_had_errors: bool = False,
        result_request_retry: bool = False,
        result_message: str = "",
        result_data: dict = {},
        result_in_ticket: bool = False,
        result_time: datetime = None,
        playbook_done: bool = False,
        result_exception=None,
        result_was_successful=False,
    ):
        self.playbook = playbook
        self.stage: int = stage
        self.title = title
        self.description = description
        self.start_time: datetime = start_time
        self.related_ticket_number: str = ""
        self.result_was_successful: bool = result_was_successful
        self.result_had_warnings: bool = result_had_warnings
        self.result_had_errors: bool = result_had_errors
        self.result_request_retry: bool = result_request_retry
        self.result_message: str = result_message
        self.result_data: dict = result_data
        self.result_in_ticket = result_in_ticket
        self.result_time: datetime = result_time if result_time is not None else datetime.datetime.now()
        self.result_exception: str = result_exception
        self.result_warning_messages: List = []
        self.stage_done: bool = False
        self.playbook_done: bool = playbook_done

    def set_successful(self, message: str = "The action taken was successful.", data: dict = None, ticket_number=None) -> bool:
        """Sets the audit log element as successful. If a ticket number is given, "result_in_ticket" is automatically set to True."""
        self.result_was_successful = True
        self.result_request_retry = False
        self.result_message = message
        self.result_data["success"] = data
        self.result_time = datetime.datetime.now()
        if ticket_number is not None:
            self.result_in_ticket = True
            self.related_ticket_number = ticket_number
        self.stage_done = True
        return self

    def set_warning(
        self, in_ticket: bool = False, warning_message: str = "The action taken had warnings, but succeeded", data: dict = None
    ) -> bool:
        """Sets the audit log element as successful, but with warnings (no retry)."""
        self.result_had_warnings = True
        self.result_had_errors = False
        self.result_request_retry = False
        self.result_warning_messages.append(warning_message)
        self.result_data["warnings"] = data
        self.result_in_ticket = in_ticket
        self.result_time = datetime.datetime.now()
        self.stage_done = True
        return self

    def set_error(
        self,
        in_ticket: bool = False,
        message: str = "The action taken had errors and failed. Requested retry.",
        data: dict = None,
        exception=None,
    ) -> bool:
        """Sets the audit log element as failed with errors (with retry request)."""
        self.result_had_errors = True
        self.result_request_retry = True
        self.result_message = message
        self.result_data["error"] = data
        self.result_in_ticket = in_ticket
        self.result_time = datetime.datetime.now()
        self.result_exception = str(exception)
        self.stage_done = True
        return self

    def __dict__(self):
        """Returns the dictionary representation of the object.
        It will only return the result_* attributes if the stage is done to enhance readability.
        """
        if self.stage_done:
            dict_ = {
                "playbook": self.playbook,
                "stage": self.stage,
                "title": self.title,
                "description": self.description,
                "start_time": str(self.start_time),
                "related_ticket_number": self.related_ticket_number,
                "result_was_successful": self.result_was_successful,
                "result_had_warnings": self.result_had_warnings,
                "result_had_errors": self.result_had_errors,
                "result_request_retry": self.result_request_retry,
                "result_message": self.result_message,
                "result_data": str(self.result_data),
                "result_exception": self.result_exception,
                "result_warning_messages": self.result_warning_messages,
                "result_in_ticket": self.result_in_ticket,
                "result_time": str(self.result_time),
                "playbook_done": self.playbook_done,
                "stage_done": self.stage_done,
            }
        else:
            dict_ = {
                "playbook": self.playbook,
                "stage": self.stage,
                "title": self.title,
                "description": self.description,
                "start_time": str(self.start_time),
                "related_ticket_number": self.related_ticket_number,
                "playbook_done": self.playbook_done,
                "stage_done": self.stage_done,
            }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class CaseFile:
    """CaseFile class. This class is used for storing one or multiple detections in an unified case object.

    Attributes:
        detections (List[Detection]): The detections of the case
        playbooks (List[str]): The playbooks of the case
        action (str): The action of the case
        action_result (bool): The action result of the case
        action_result_message (str): The action result message of the case
        action_result_data (str): The action result data of the case
        context_logs (List[ContextLog]): The context logs of the case
        context_processes (List[Process]): The context processes of the case
        context_flows (List[ContextFlow]): The context flows of the case
        context_threat_intel (List[ContextThreatIntel]): The context threat intel of the case
        context_files (List[File]): The context files of the case
        context_http_requests (List[HTTP]): The context http requests of the case
        context_dns_requests (List[DNS]): The context dns requests of the case
        context_certificates (List[Certificate]): The context certificates of the case
        context_registries (List[Registry]): The context registries of the case
        context_tickets (List[Ticket]): The context tickets of the case
        uuid (str): The universal unique ID of the case (uuid4 - random if not set)
        indicators (Dict[str, List[str]]): The indicators of the case (key: indicator type, value: list of indicators)


    Methods:
        __init__(self, detections: List[Detection], uuid: uuid.UUID = uuid.uuid4()): Initializes the CaseFile object.
        __str__(self): Returns the string representation of the object.
        add_context_log(self, context: Union[ContextLog, ContextProcess, ContextFlow, ContextThreatIntel, Location, Device, Person, ContextFile]): Adds a context to the case.
        get_context_by_uuid(self, uuid: str, filterType: type (optional)): Returns the context by the given uuid.
    """

    def __init__(self, detections: list, uuid: uuid.UUID = uuid.uuid4()):
        self.detections = detections
        if type(detections) != list:
            self.detections = [detections]

        self.procedure_step = (
            "initial"  # One of "initial", "gather_information", "analyze", "containment", "eradication", "closure"
        )
        self.status = "unresolved"  # One of "unresolved", "resolved"
        self.threat_type = "undetermined"  # One of "undetermined", "unknown", "known"
        self.threat_level = "undetermined"  # One of "undetermined", "negligible", "low", "medium", "high", "critical"
        self.result = "undetermined"  # One of "undetermined", "false-positive", "non-issue", "alert", "incident", "breach"
        self.result_confidence = 0  # 0-100
        self.playbooks = []
        self.audit_trail: List[AuditLog] = [
            AuditLog(
                playbook="None/Initial",
                stage=0,
                title="Initializing CaseFile",
                description="Initializing the CaseFile onject",
                start_time=datetime.datetime.now(),
                is_ticket_related=False,
            )
        ]
        self.handled_by_playbooks: List[str] = []
        self.playbooks_to_retry: List[str] = []
        self.ticket: pyotrs.Ticket = None

        # Context for every type of context
        self.context_logs: List[ContextLog] = []
        self.context_processes: List[ContextProcess] = []
        self.context_flows: List[ContextFlow] = []
        self.context_threat_intel: List[ContextThreatIntel] = []
        self.context_locations: List[Location] = []
        self.context_devices: List[ContextDevice] = []
        self.context_persons: List[Person] = []
        self.context_files: List[ContextFile] = []
        self.context_registries: List[ContextRegistry] = []

        self.uuid = uuid
        self.indicators = {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": [],
            "email": [],
            "countries": [],
            "registry": [],
            "other": [],
        }

        self.audit_trail[0].result_had_warnings = False
        self.audit_trail[0].result_had_errors = False
        self.audit_trail[0].result_request_retry = False
        self.audit_trail[0].result_in_ticket = False
        self.audit_trail[0].result_message = "Initializing CaseFile was successful."
        self.audit_trail[0].result_data = "CaseFile was initialized successfully."

    def __dict__(self):
        """Returns the object as a dictionary."""
        dict_ = {
            "detections": self.detections,
            "handled_by_playbooks": self.handled_by_playbooks,
            "action": self.action,
            "ticket_number": self.get_ticket_number() if self.ticket else None,
            "action_result": self.action_result,
            "action_result_message": self.action_result_message,
            "action_result_data": self.action_result_data,
            "context_logs": str(self.context_logs),
            "context_processes": str(self.context_processes),
            "context_flows": str(self.context_flows),
            "context_threat_intel": str(self.context_threat_intel),
            "context_locations": str(self.context_locations),
            "context_devices": str(self.context_devices),
            "context_persons": str(self.context_persons),
            "context_files": str(self.context_files),
            "context_registries": str(self.context_registries),
            "uuid": self.uuid,
            "indicators": self.indicators,
            "audit_trail": self.audit_trail,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    def add_context(
        self,
        context: Union[
            ContextLog,
            ContextProcess,
            ContextFlow,
            ContextThreatIntel,
            Location,
            ContextDevice,
            Person,
            ContextFile,
            ContextRegistry,
            HTTP,
            DNSQuery,
            Certificate,
            dict,
        ],
    ):
        """Adds a context to the detection case, respecting the timeline

        Args:
            context (Union[ContextLog, ContextProcess, ContextFlow, ContextThreatIntel, Location, Device, Person, ContextFile, HTTP, DNSQuery, Certificate, dict]): The context to add (dict menas Ticket object)

        Raises:
            ValueError: If the context object has no timestamp
            TypeError: If the context object is not of a valid type
        """
        if context is None:
            mlog = logging_helper.Log(__name__)
            mlog.warning("CaseFile: add_context() - Context is None, skipping.")
            return

        if not isinstance(context, dict) and not isinstance(context, pyotrs.Ticket):
            try:
                timestamp = context.timestamp
            except:
                raise ValueError("Context object has no timestamp.")
        elif type(context) is dict:
            timestamp = context["Ticket"]["Created"]
        else:
            timestamp = context.field_get("Created")

        if isinstance(context, ContextLog):
            add_to_timeline(self.context_logs, context, timestamp)
            if context.log_flow:
                self.indicators["ip"].append(context.log_flow.source_ip)
                self.indicators["ip"].append(context.log_flow.destination_ip)

        elif isinstance(context, ContextProcess):
            add_to_timeline(self.context_processes, context, timestamp)
            if context.process_flow:
                self.indicators["ip"].append(context.process_flow.source_ip)
                self.indicators["ip"].append(context.process_flow.destination_ip)
            if context.process_md5:
                self.indicators["hash"].append(context.process_md5)
            if context.process_sha1:
                self.indicators["hash"].append(context.process_sha1)
            if context.process_sha256:
                self.indicators["hash"].append(context.process_sha256)

        elif isinstance(context, ContextFlow):
            add_to_timeline(self.context_flows, context, timestamp)
            self.indicators["ip"].append(context.source_ip)
            self.indicators["ip"].append(context.destination_ip)

            if context.http:
                self.indicators["domain"].append(context.http.host)
                self.indicators["url"].append(context.http.full_url)
                if context.http.request_body:
                    self.indicators["other"].append(context.http.request_body)
                if context.http.file:
                    self.indicators["other"].append(context.http.file.file_name)
                    if context.http.file.file_md5:
                        self.indicators["hash"].append(context.http.file.file_md5)
                    if context.http.file.file_sha1:
                        self.indicators["hash"].append(context.http.file.file_sha1)
                    if context.http.file.file_sha256:
                        self.indicators["hash"].append(context.http.file.file_sha256)

            if context.dns_query:
                self.indicators["domain"].append(context.dns_query.query)
                if context.dns_query.query_response and cast_to_ipaddress(context.dns_query.query_response):
                    self.indicators["ip"].append(context.dns_query.query_response)

            if context.http and context.http.certificate:
                self.indicators["domain"].append(context.http.certificate.subject)
                if (
                    context.http.certificate.subject_alternative_names is not None
                    and len(context.http.certificate.subject_alternative_names) > 0
                ):
                    for san in context.http.certificate.subject_alternative_names:
                        self.indicators["domain"].append(san)

        elif isinstance(context, ContextThreatIntel):
            add_to_timeline(self.context_threat_intel, context, timestamp)

        elif isinstance(context, Location):
            add_to_timeline(self.context_locations, context, timestamp)
            if context.country:
                self.indicators["countries"].append(context.country)

        elif isinstance(context, ContextDevice):
            add_to_timeline(self.context_devices, context, timestamp)
            if context.local_ip:
                self.indicators["ip"].append(context.local_ip)
            if context.global_ip:
                self.indicators["ip"].append(context.global_ip)

        elif isinstance(context, Person):
            add_to_timeline(self.context_persons, context, timestamp)

        elif isinstance(context, ContextRegistry):
            add_to_timeline(self.context_registries, context, timestamp)
            registry_indicator = context.registry_key.lower() + "->" + context.registry_value.lower()
            self.indicators["registry"].append(registry_indicator)

        elif isinstance(context, ContextFile):
            add_to_timeline(self.context_files, context, timestamp)
            self.indicators["other"].append(context.file_name)
            if context.file_md5:
                self.indicators["hash"].append(context.file_md5)
            if context.file_sha1:
                self.indicators["hash"].append(context.file_sha1)
            if context.file_sha256:
                self.indicators["hash"].append(context.file_sha256)

        elif isinstance(context, dict) or isinstance(context, pyotrs.Ticket):
            if isinstance(context, pyotrs.Ticket) or context["Ticket"]:
                self.ticket = context
            else:
                raise TypeError("Given dict was no valid ticket object.")

        else:
            raise TypeError("Unknown context type.")

        # Remove '*.' from domain indicators and replace with empty
        for domain in self.indicators["domain"]:
            if domain.startswith("*"):
                mlog = logging_helper.Log("lib.class_helper")
                mlog.debug("Removing '*.' from domain indicator: " + domain)
                self.indicators["domain"].remove(domain)
                self.indicators["domain"].append(domain[2:])

        # Remove duplicates
        remove_duplicates_from_dict(self.indicators)
        return

    def get_context_by_uuid(
        self, uuid: str, filterType: type = None
    ) -> Union[ContextLog, ContextProcess, ContextFlow, ContextThreatIntel, Location, ContextDevice, Person, ContextFile]:
        """Returns the context with the given UUID

        Args:
            uuid (str): The UUID of the context
            filterType (type, optional): The type of the context. Defaults to None.

        Returns:
            Union[ContextLog, ContextProcess, ContextFlow, ContextThreatIntel, Location, Device, Person, ContextFile]: The context
        """
        if filterType == ContextLog or filterType is None:
            for context in self.context_logs:
                if context.uuid == uuid:
                    return context

        if filterType == ContextProcess or filterType is None:
            for context in self.context_processes:
                if context.uuid == uuid:
                    return context

        if filterType == ContextFlow or filterType is None:
            for context in self.context_flows:
                if context.uuid == uuid:
                    return context

        if filterType == ContextThreatIntel or filterType is None:
            for context in self.context_threat_intel:
                if context.uuid == uuid:
                    return context

        if filterType == Location or filterType is None:
            for context in self.context_locations:
                if context.uuid == uuid:
                    return context

        if filterType == ContextDevice or filterType is None:
            for context in self.context_devices:
                if context.uuid == uuid:
                    return context

        if filterType == Person or filterType is None:
            for context in self.context_persons:
                if context.uuid == uuid:
                    return context

        if filterType == ContextFile or filterType is None:
            for context in self.context_files:
                if context.uuid == uuid:
                    return context

        if filterType == pyotrs.Ticket or filterType is None:
            for context in self.context_tickets:
                if context.tid == uuid:
                    return context

        return None

    def get_audit_by_playbook(self, playbook: str) -> List[AuditLog]:
        """Returns the audit of the given playbook

        Args:
            playbook (str): The playbook

        Returns:
            List[audit]: The audit
        """
        audit = []
        for h in self.audit_trail:
            if h.playbook == playbook:
                audit.append(h)
        return audit

    def get_audit_by_playbook_stage(self, playbook: str, stage: int) -> List[AuditLog]:
        """Returns the audit of the given playbook and stage

        Args:
            playbook (str): The playbook
            stage (int): The stage

        Returns:
            List[audit]: The audit
        """
        audit = []
        for h in self.audit_trail:
            if h.playbook == playbook and h.stage == stage:
                audit.append(h)
        return audit

    def get_tries_by_playbook(self, playbook: str) -> int:
        """Returns the number of tries for the given playbook

        Args:
            playbook (str): The playbook

        Returns:
            int: The number of tries
        """
        tries = 0
        # Check for playbook in audit_trail and add count for each element which has stage number 0 (first try).
        for h in self.audit_trail:
            if h.playbook == playbook and h.stage == 0:
                tries += 1

    def update_audit(self, audit: AuditLog, logger=None):
        """Adds or updates the given audit element to the audit_trail of the case.
           It will also update apropiate fields of the case if the playbook was executed successfully or has failed.
           Also the audit will be added to "audit.log" file (sorted by detection uuid).

        Args:
            audit (auditElement): The audit element
            logger (Log): The logger object (optional) Set if the audit shall be logged to the normal log file as well

        Raises:
            TypeError: If the audit element is not of type AuditElement
        """
        if type(audit) is not AuditLog:
            raise TypeError("audit must be of type AuditElement")

        if audit.playbook_done:
            self.handled_by_playbooks.append(audit.playbook)
        if audit.result_request_retry:
            self.playbooks_to_retry.append(audit.playbook)

        if audit.result_data is None:
            audit.result_data = {}
        audit.result_data["detection_name"] = self.detections[
            0
        ].name  # Add detection name to result data for better overview in log entries

        for h in self.audit_trail:
            if h.playbook == audit.playbook and h.stage == audit.stage:
                self.audit_trail.remove(h)

        self.audit_trail.append(audit)

        # Add to audit.log
        logging_helper.update_audit_log(self.uuid, audit, logger)

    def get_title(self):
        """Returns the title of the case."""
        rules = []
        try:
            for detection in self.detections:
                for rule in detection.rules:
                    rules.append(rule.name)
            if len(rules) > 0:
                return rules[0]
        except:
            pass
        return self.detections[0].name

    def get_ticket_number(self):
        """Returns the ticket number of the case."""
        if self.ticket is not None:
            try:
                return self.ticket["TicketNumber"]
            except:
                return self.ticket.field_get("TicketNumber")
        else:
            raise ValueError("The case_file has no ticket.")

    def get_ticket_id(self):
        """Returns the ticket id of the case."""
        if self.ticket is not None:
            try:
                return self.ticket["TicketID"]
            except:
                return self.ticket.field_get("TicketID")
        else:
            raise ValueError("The case_file has no ticket.")

    def get_ticket_title(self):
        """Returns the ticket title of the case."""
        if self.ticket is not None:
            try:
                return self.ticket["Title"]
            except:
                return self.ticket.field_get("Title")
        else:
            raise ValueError("The case_file has no ticket.")
