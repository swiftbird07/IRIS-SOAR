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

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper

DEFAULT_IP = ipaddress.ip_address("127.0.0.1")  # When no IP address is provided, this is used

# TODO: Implement all functions used by zsoar_worker.py and its modules


def cast_to_ipaddress(ip) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """Tries to cast a string to an IP address.

    Args:
        ip: The IP address to cast

    Returns:
        ipaddress.IPv4Address or ipaddress.IPv6Address: The IP address object

    Raises:
        ValueError: If the IP address is invalid
    """
    if type(ip) != ipaddress.IPv4Address and type(ip) != ipaddress.IPv6Address and type(ip) != None:
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("invalid ip address: " + str(ip))
    return ip


def del_none_from_dict(d):
    """
    Delete keys with the value ``None`` in a dictionary, recursively.

    This alters the input so you may wish to ``copy`` the dict first.

    Args:
        d (dict): The dictionary to remove the keys from

    Returns:
        dict: The cleaned dictionary
    """
    # For Python 3, write `list(d.items())`; `d.items()` won’t work
    # For Python 2, write `d.items()`; `d.iteritems()` won’t work
    if d is None:
        return None
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif type(value) is list:
            for item in value:
                if isinstance(item, dict):
                    del_none_from_dict(item)
        elif str(value) == "[]":  # Remove trivial empty strings
            del d[key]
        elif type(value) is str and value == "":  # Remove trivial empty strings
            del d[key]
        elif isinstance(value, dict):
            del_none_from_dict(value)
    return d  # For convenience


def handle_percentage(percentage):
    """Handles a percentage value.

    Args:
        percentage (int): The percentage value

    Returns:
        int: The percentage value

    Raises:
        TypeError: If the percentage value is not an integer
        ValueError: If the percentage value is higher than 100 or lower than 0
    """
    if percentage is None:
        return None
    if type(percentage) != int:
        raise TypeError("Percentage value must be an integer")
    if percentage > 100:
        raise ValueError("Percentage value cannot be higher than 100")
    if percentage < 0:
        raise ValueError("Percentage value cannot be lower than 0")
    return percentage


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
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the Vulnerability object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class Service:
    """Service class. This class is used for storing service information.

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


class Device:
    """Device class. This class is used for storing device information.

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
        last_update (datetime): The date and time when the device was last updated
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
        hypervisor=None,  # can't state that here, but type has to be 'Device'
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
        self.local_ip = cast_to_ipaddress(local_ip)
        self.global_ip = cast_to_ipaddress(global_ip)

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
            if type(hypervisor) == Device:
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
        severity (int): The severity of the rule
        tags (List[str]): The tags of the rule
        raw (str): The raw rule
        created_at (datetime): The creation date of the rule
        updated_at (datetime): The last update date of the rule


    Methods:
        __init__(self, id: str, name: str, severity: int, description: str = None, tags: List[str] = None, raw: str = None, created_at: datetime = None, updated_at: datetime = None)
        __str__(self)
    """

    def __init__(
        self,
        id: str,
        name: str,
        severity: int,
        description: str = None,
        tags: List[str] = None,
        raw: str = None,
        created_at: datetime.datetime = None,
        updated_at: datetime.datetime = None,
    ):
        mlog = logging_helper.Log("lib.class_helper")

        if type(id) is not str:
            mlog.warning("The ID of the rule is not a string: " + str(id) + ". Converting to string.")
            id = str(id)

        # TODO: (for all classes) Add type checks for strings as well

        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.tags = tags
        self.raw = raw
        self.created_at = created_at
        self.updated_at = updated_at

    def __dict__(self):
        """Returns the dictionary representation of the object."""
        dict_ = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
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


class Detection:
    """Detection class. This class is used for storing detections.

    Attributes:
        vendor_id (str): The vendor specific ID of the detection, note that for unique identification, the 'uuid' of the detection is used
        name (str): The name of the detection
        rules (List[Rule]): The rules that triggered the detection
        description (str): The description of the detection
        tags (List[str]): The tags of the detection
        raw (str): The raw detection
        timestamp (datetime): The timestamp of the detection
        source (str): The source of the detection
        source_ip (socket.inet_aton): The source IP of the detection
        source_port (int): The source port of the detection
        destination (str): The destination of the detection
        destination_ip (datetime): The destination IP of the detection
        destination_port (int): The destination port of the detection
        protocol (str): The protocol of the detection
        severity (int): The severity of the detection
        process (ContextProcess): The process of the detection

    Methods:
        __init__(self, id: str, name: str, rules: List[Rule], description: str = None, tags: List[str] = None, raw: str = None, timestamp: datetime = None, source: str = None, source_ip: socket.inet_aton = None, source_port: int = None, destination: str = None, destination_ip: datetime = None, destination_port: int = None, protocol: str = None, severity: int = None, process: ContextProcess = None)
        __str__(self)
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
        source: str = None,
        source_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP,
        source_port: int = None,
        destination: str = None,
        destination_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = DEFAULT_IP,
        destination_port: int = None,
        protocol: str = None,
        severity: int = None,
        uuid: uuid.UUID = uuid.uuid4(),
    ):
        source_ip = cast_to_ipaddress(source_ip)
        destination_ip = cast_to_ipaddress(destination_ip)

        self.vendor_id = vendor_id
        self.name = name
        self.description = description
        self.timestamp = timestamp
        self.source = source
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination = destination
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.severity = severity
        self.tags = tags
        self.raw = raw
        self.rules = rules

        self.uuid = uuid

    def __dict__(self):
        """Returns the dictionary representation of the object."""
        dict_ = {
            "id": self.vendor_id,
            "name": self.name,
            "description": self.description,
            "timestamp": self.timestamp,
            "source": self.source,
            "source_ip": str(self.source_ip),
            "source_port": self.source_port,
            "destination": self.destination,
            "destination_ip": str(self.destination_ip),
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "tags": self.tags,
            "raw": self.raw,
            "rules": self.rules,
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    # ...


class NetworkFlow:
    """This class provides a single context of type flow for a detection.

    Attributes:
        related_detection_uuid (str): The related detection unique ID of the context flow
        timestamp (datetime): The timestamp of the flow
        integration (str): The integration of the flow
        source_ip (socket.inet_aton): The source IP of the flow
        source_port (int): The source port of the flow
        destination_ip (socket.inet_aton): The destination IP of the flow
        destination_port (int): The destination port of the flow
        protocol (str): The protocol of the flow
        data (str): The data of the flow
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
        application: str = None,
        data: str = None,
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
    ):
        source_ip = cast_to_ipaddress(source_ip)
        destination_ip = cast_to_ipaddress(destination_ip)

        if flow_id < 1 or flow_id > 1000000000:
            raise ValueError("flow_id must be between 1 and 1000000000")

        self.related_detection_uuid = related_detection_uuid

        self.timestamp = timestamp
        self.data = data
        self.integration = integration

        self.source_ip = source_ip
        self.source_port = source_port

        self.destination_ip = destination_ip
        self.destination_port = destination_port

        self.protocol = protocol
        self.application = application

        self.source_mac = source_mac
        self.destination_mac = destination_mac

        self.source_hostname = source_hostname
        self.destination_hostname = destination_hostname

        self.category = category
        self.sub_category = sub_category

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

    def __dict__(self):
        # Have to overwrite the __dict__ method because of the ipaddress objects

        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "integration": self.integration,
            "source_ip": str(self.source_ip),
            "source_port": self.source_port,
            "destination_ip": str(self.destination_ip),
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "application": self.application,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "source_hostname": self.source_hostname,
            "destination_hostname": self.destination_hostname,
            "category": self.category,
            "sub_category": self.sub_category,
            "flow_direction": self.flow_direction,
            "flow_id": self.flow_id,
            "interface": self.interface,
            "network": self.network,
            "network_type": self.network_type,
            "flow_source": self.flow_source,
        }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    # ...


class Certificate:
    """Certificate class.

    Attributes:
        related_detection_uuid (str): The UUID of the related detection
        flow (ContextFlow): The flow of the certificate
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


    Methods:
        __init__(self, flow: ContextFlow, subject: str, issuer: str, issuer_common_name: str = None, issuer_organization: str = None, issuer_organizational_unit: str = None, serial_number: str = None, subject_common_name: str = None, subject_organization: str = None, subject_organizational_unit: str = None, subject_alternative_name: str = None, valid_from: datetime = None, valid_to: datetime = None, version: str = None, signature_algorithm: str = None, public_key_algorithm: str = None, public_key_size: int = None)
        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        flow: NetworkFlow,
        subject: str,
        issuer: str,
        issuer_common_name: str = None,
        issuer_organization: str = None,
        issuer_organizational_unit: str = None,
        serial_number: str = None,
        subject_common_name: str = None,
        subject_organization: str = None,
        subject_organizational_unit: str = None,
        subject_alternative_name: str = None,
        valid_from: datetime = None,
        valid_to: datetime = None,
        version: str = None,
        signature_algorithm: str = None,
        public_key_algorithm: str = None,
        public_key_size: int = None,
    ):
        self.related_detection_uuid = related_detection_uuid
        self.flow = flow
        self.issuer = issuer
        self.issuer_common_name = issuer_common_name
        self.issuer_organization = issuer_organization
        self.issuer_organizational_unit = issuer_organizational_unit
        self.serial_number = serial_number
        self.subject = subject
        self.subject_common_name = subject_common_name
        self.subject_organization = subject_organization
        self.subject_organizational_unit = subject_organizational_unit
        self.subject_alternative_name = subject_alternative_name

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

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "flow": self.flow,
            "subject": self.subject,
            "issuer": self.issuer,
            "issuer_common_name": self.issuer_common_name,
            "issuer_organization": self.issuer_organization,
            "issuer_organizational_unit": self.issuer_organizational_unit,
            "serial_number": self.serial_number,
            "subject_common_name": self.subject_common_name,
            "subject_organization": self.subject_organization,
            "subject_organizational_unit": self.subject_organizational_unit,
            "subject_alternative_name": self.subject_alternative_name,
            "valid_from": str(self.valid_from),
            "valid_to": str(self.valid_to),
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_size": self.public_key_size,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class DNSQuery:
    """DNSQuery class.

    Attributes:
        related_detection_uuid (str): The UUID of the related detection
        flow (ContextFlow): The flow of the DNS query
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
        flow: NetworkFlow,
        type: str,
        query: str,
        has_response: bool = False,
        query_response: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, str] = DEFAULT_IP,
        rcode: str = "NOERROR",
    ):
        self.related_detection_uuid = related_detection_uuid
        self.flow = flow

        if type not in ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]:
            raise ValueError("type must be one of A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT")

        self.type = type
        self.query = query

        self.has_response = has_response
        if not has_response and query_response != DEFAULT_IP:
            raise ValueError("query_response must be DEFAULT_IP if has_response is False")
        if has_response and query_response == DEFAULT_IP:
            mlog = logging_helper.Log("lib.class_helper")
            mlog.warning("DNSQuery Object __init__: query_response is still DEFAULT_IP while has_response is True.", str(self))
        self.query_response = query_response

        self.rcode = rcode

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "flow": self.flow,
            "type": self.type,
            "query": self.query,
            "has_response": self.has_response,
            "query_response": str(self.query_response),
            "rcode": self.rcode,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class HTTP:
    """HTTP class.

    Attributes:
        related_detection_uuid (str): The UUID of the related detection
        flow (ContextFlow): The flow of the HTTP request
        method (str): The method of the HTTP request
        type (str): The type of the HTTP request
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

    Methods:

        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        flow: NetworkFlow,
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
    ):
        self.related_detection_uuid = related_detection_uuid
        mlog = logging_helper.Log("lib.class_helper")
        self.flow = flow

        if method not in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]:
            raise ValueError("method must be one of GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH")
        self.method = method

        if type not in ["HTTP", "HTTPS"]:
            raise ValueError("type must be one of HTTP, HTTPS")
        self.type = type

        if host == "":
            raise ValueError("host must not be empty")
        self.host = host

        if status_code < 0 or status_code > 999:
            raise ValueError("status_code must be between 0 and 999")
        self.status_code = status_code

        if path != None and "/" not in path:
            mlog.warning("HTTP Object __init__: path does not contain any '/'. Path: '" + str(path) + "' Object: " + str(self))
        if path[0] != "/":
            self.path = "/" + path
        else:
            self.path = path

        if full_url == None:
            self.full_url = type.lower() + "://" + host + self.path
        else:
            if full_url != type.lower() + "://" + host + self.path:
                mlog.warning("HTTP Object __init__: full_url does not match type, host and path. " + str(self))
            self.full_url = full_url

        self.user_agent = user_agent
        self.referer = referer

        self.status_message = (
            status_message  # TODO: Maybe enrich, when empty, with dict values from https://gist.github.com/bl4de/3086cf26081110383631
        )

        self.request_body = request_body
        self.response_body = response_body
        self.request_headers = request_headers
        self.response_headers = response_headers

        if http_version != None and ["1.", "2.", "3."] not in http_version:
            raise ValueError("http_version must be one of 1.x, 2.x, 3.x if not None")
        self.http_version = http_version

    def __dict__(self):
        try:
            dict_ = {
                "related_detection_uuid": self.related_detection_uuid,
                "flow": self.flow,
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
                "response_body": self.response_body,
                "request_headers": self.request_headers,
                "response_headers": self.response_headers,
                "http_version": self.http_version,
            }
        except AttributeError:
            dict_ = {
                "flow": self.flow,
                "method": self.method,
                "type": self.type,
                "host": self.host,
                "status_code": self.status_code,
            }

        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class File:
    """File class. Represents a file.

    Attributes:
        related_detection_uuid (uuid.UUID): The UUID of the detection the file is related to
        file_name (str): The name of the file
        file_path (str): The path of the file
        file_size (int): The size of the file
        file_md5 (str): The MD5 hash of the file
        file_sha1 (str): The SHA1 hash of the file
        file_sha256 (str): The SHA256 hash of the file
        file_type (str): The type of the file
        file_extension (str): The extension of the file
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

    Methods:
        __init__(self, file_name: str, file_path: str, file_size: int, file_md5: str, file_sha1: str, file_sha256: str,
            file_type: str, file_extension: str, is_encrypted: bool, is_compressed: bool, is_archive: bool, is_executable: bool,
            is_readable: bool, is_writable: bool, is_hidden: bool, is_system: bool, is_temporary: bool, is_virtual: bool,
            is_directory: bool, is_symlink: bool, is_special: bool, is_unknown: bool): The constructor of the File class
        __str__(self): The string representation of the File class
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        file_name: str,
        file_path: str = "",
        file_size: int = 0,
        file_md5: str = "",
        file_sha1: str = "",
        file_sha256: str = "",
        file_type: str = "",
        file_extension: str = "",
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
    ):
        self.related_detection_uuid = related_detection_uuid
        self.file_name = file_name
        self.file_path = file_path

        if file_size < 0:
            raise ValueError("file_size must not be negative")
        self.file_size = file_size

        self.file_md5 = file_md5
        self.file_sha1 = file_sha1
        self.file_sha256 = file_sha256

        self.file_type = file_type

        if file_extension != "" and file_extension[0] == ".":  # File extension should not start with a dot in the variable
            file_extension = file_extension[1:]
        self.file_extension = file_extension

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

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": self.related_detection_uuid,
            "file_name": self.file_name,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_md5": self.file_md5,
            "file_sha1": self.file_sha1,
            "file_sha256": self.file_sha256,
            "file_type": self.file_type,
            "file_extension": self.file_extension,
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
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class Process:
    """Process class.

    Attributes:
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
        process_certificate (Certificate): The certificate object of the process
        process_http (HTTP): The HTTP object of the process
        process_flow (ContextFlow): The flow object of the process
        process_parent (ContextProcess): The parent process object of the process
        process_children (List[ContextProcess]): The children processes of the process
        process_environment_variables (List[]): The environment variables of the process
        process_arguments (List[]): The arguments of the process
        process_modules (List[]): The modules of the process
        process_thread (str): The threads of the process

    Methods:
        __init__(self, process_name: str, process_id: int, parent_process_name: str = "N/A", parent_process_id: int = 0, process_path: str = "", process_md5: str = "", process_sha1: str = "", process_sha256: str = "", process_command_line: str = "", process_username: str = "", process_integrity_level: str = "", process_is_elevated_token: bool = False, process_token_elevation_type: str = "", process_token_elevation_type_full: str = "", process_token_integrity_level: str = "", process_token_integrity_level_full: str = "", process_privileges: str = "", process_owner: str = "", process_group_id: int = "", process_group_name: str = "", process_logon_guid: str = "", process_logon_id: str = "", process_logon_type: str = "", process_logon_type_full: str = "", process_logon_time: str = "", process_start_time: str = "", process_parent_start_time: str = "", process_current_directory: str = "", process_image_file_device: str = "", process_image_file_directory: str = "", process_image_file_name: str = "", process_image_file_path: str = "", process_dns: DNSQuery = None, process_certificate: Certificate = None, process_http: HTTP = None, process_flow: ContextFlow = None, process_parent: ContextProcess = None, process_children: List[ContextProcess] = None, process_environment_variables: List[] = None, process_arguments: List[] = None, process_modules: List[] = None, process_thread: str = "")
        __str__(self)
    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        process_name: str,
        process_id: int,
        parent_process_name: str = "N/A",
        parent_process_id: int = 0,
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
        process_certificate: Certificate = None,
        process_http: HTTP = None,
        process_flow: NetworkFlow = None,
        process_parents: list = [],
        process_children: list = [],
        process_environment_variables: List[str] = [],
        process_arguments: List[str] = [],
        process_modules: List[str] = [],
        process_thread: str = None,
    ):
        self.related_detection_uuid = related_detection_uuid

        if process_name == "":
            raise ValueError("process_name cannot be empty")
        self.process_name = process_name

        if process_id < 0:
            raise ValueError("process_id cannot be negative")
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
        self.process_certificate = process_certificate
        self.process_http = process_http
        self.process_flow = process_flow

        for parent in process_parents:
            if not isinstance(parent, Process):
                raise TypeError("all process_parents must be of type ContextProcess. Got: " + str(type(parent)) + "for " + str(parent))
        self.process_parents = process_parents

        for child in process_children:
            if not isinstance(child, Process):
                raise TypeError("all process_children must be of type ContextProcess. Got: " + str(type(child)) + "for " + str(child))
        self.process_children = process_children

        self.process_environment_variables = process_environment_variables
        self.process_arguments = process_arguments
        self.process_modules = process_modules
        self.process_thread = process_thread

    def __dict__(self):
        _dict = {
            "related_detection_uuid": self.related_detection_uuid,
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
            "process_certificate": self.process_certificate,
            "process_http": self.process_http,
            "process_flow": self.process_flow,
            "process_parents": self.process_parents,
            "process_children": self.process_children,
            "process_environment_variables": self.process_environment_variables,
            "process_arguments": self.process_arguments,
            "process_modules": self.process_modules,
            "process_thread": self.process_thread,
        }
        return _dict

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(del_none_from_dict(self.__dict__())), indent=4, sort_keys=False, default=str)


class LogMessage:
    """The LogMessage class. Used for storing log data like syslog from a SIEM.

    Attrbutes:
        related_detection_uuid (uuid.UUID): The UUID of the detection this log is related to
        log_message (str): The message of the log
        log_source (str): The source of the log
        log_flow (ContextFlow): The flow object related to the log
        log_protocol (str): The protocol of the log
        log_timestamp (datetime.datetime): The timestamp of the log
        log_type (str): The type of the log
        log_severity (str): The severity of the log
        log_facility (str): The facility of the log
        log_tags (List[str]): The tags of the log
        log_custom_fields (dict): The custom fields of the log

    Methods:
        __init__(log_message, log_source, log_flow, log_protocol, log_timestamp, log_type, log_severity, log_facility, log_tags, log_custom_fields): Initializes the ContextLog object
        __str__(self): Returns the ContextLog object as a string

    """

    def __init__(
        self,
        related_detection_uuid: uuid.UUID,
        log_timestamp: datetime.datetime,
        log_message: str,
        log_source: str,
        log_flow: NetworkFlow = None,
        log_protocol: str = "",
        log_type: str = "",
        log_severity: str = "",
        log_facility: str = "",
        log_tags: List[str] = None,
        log_custom_fields: dict = None,
    ):
        self.related_detection_uuid = related_detection_uuid
        self.log_timestamp = log_timestamp
        self.log_message = log_message
        self.log_source = log_source
        self.log_flow = log_flow
        self.log_protocol = log_protocol
        self.log_type = log_type
        self.log_severity = log_severity
        self.log_facility = log_facility
        self.log_tags = log_tags
        self.log_custom_fields = log_custom_fields

    def __dict__(self):
        dict_ = {
            "related_detection_uuid": str(self.related_detection_uuid),
            "log_timestamp": str(self.log_timestamp),
            "log_message": self.log_message,
            "log_source": self.log_source,
            "log_flow": self.log_flow,
            "log_protocol": self.log_protocol,
            "log_type": self.log_type,
            "log_severity": self.log_severity,
            "log_facility": self.log_facility,
            "log_tags": self.log_tags,
            "log_custom_fields": self.log_custom_fields,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)


class ThreatIntel:
    """Detection by an idividual threat intel engine (e.g. Kaspersky, Avast, Microsoft, etc.).

    Attributes:
        engine (str): The name of the detection engine
        is_known (bool): If the indicator is known by the detection engine
        is_hit (bool): If the detection engine hit on the indicator
        hit_type (str): The type of the hit (e.g. malicious, suspicious, etc.)
        threat_name (str): The name of the threat (if available)
        confidence (int): The confidence of the detection engine (if available)
        engine_version (str): The version of the detection engine
        engine_update (datetime): The last update of the detection engine
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

    def __dict__(self):
        _dict = {
            "time_requested": str(self.time_requested),
            "engine": self.engine,
            "is_known": self.is_known,
            "is_hit": self.is_hit,
            "hit_type": self.hit_type,
            "threat_name": self.threat_name,
            "confidence": self.confidence,
            "engine_version": self.engine_version,
            "engine_update": str(self.engine_update),
            "detection_last_seen": str(self.detection_last_seen),
            "detection_last_update": str(self.detection_last_update),
        }
        return _dict

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
        threat_intel_detections (List[ThreatIntelDetection]): The threat intel detections of the indicator
        score_hit (int): The hits on the particular indicator
        score_total (int): The total number of engines that were queried
        score_hit_sus (int): The number of suspicious hits on the indicator
        score_hit_mal (int): The number of malicious hits on the indicator
        score_known (int): The number of engines that know the indicator
        score_unknown (int): The number of engines that don't know the indicator
        related_detection_uuid (uuid.UUID): The UUID of the related detection

    Methods:
        __init__(type, indicator, source, timestamp, threat_intel_detections, score_hit, score_total): Initializes the ContextThreatIntel object
        __str__(self): Returns the ContextThreatIntel object as a string
    """

    def __init__(
        self,
        type: type,
        indicator: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, HTTP, DNSQuery, File, Process],
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
    ):
        if type not in [ipaddress.IPv4Address, ipaddress.IPv6Address, HTTP, DNSQuery, File, Process]:
            raise ValueError("type must be one of IPv4Address, IPv6Address, HTTP, DNSQuery, File or ContextProcess")
        self.type = type

        if not isinstance(indicator, type):
            raise ValueError("indicator must be of the given 'type'")

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
                    "Class ThreatIntel __init__: implicit calculation of score_unknown: score_unknown is not set and score_known or score_total is None. score_unknown cannot be calculated. You shouldn't see this message. Please report this issue."
                )
                raise SystemError(
                    "Class ThreatIntel __init__: implicit calculation of score_unknown: score_unknown is not set and score_known or score_total is None. score_unknown cannot be calculated. You shouldn't see this message. Please report this issue."
                )
            else:
                self.score_unknown = self.score_total - self.score_known

        self.related_detection_uuid = related_detection_uuid

        print(score_hit_sus, score_hit_mal, score_known, score_unknown)

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
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        clean_dict = del_none_from_dict(self.__dict__())
        return json.dumps(clean_dict, indent=4, sort_keys=False, default=str)


class DetectionReport:
    """DetectionReport class. This class is used for storing detection reports.

    Attributes:
        detections (List[Detection]): The detections of the report
        playbooks (List[str]): The playbooks of the report
        action (str): The action of the report
        action_result (bool): The action result of the report
        action_result_message (str): The action result message of the report
        action_result_data (str): The action result data of the report
        context_logs (List[ContextLog]): The context logs of the report
        context_processes (List[ContextProcess]): The context processes of the report
        context_flows (List[ContextFlow]): The context flows of the report
        context_threat_intel (List[ContextThreatIntel]): The context threat intel of the report
        uuid (str): The uuid of the report


    Methods:
        __init__(self, detections: List[Detection], playbooks: List[str] = None, action: str = None, action_result: bool = None, action_result_message: str = None, action_result_data: str = None, contexts: List[Context] = None): Initializes a new DetectionReport object.
        __str__(self): Returns the string representation of the object.
    """

    def __init__(self, detections: list):
        self.detections = detections
        self.playbooks: List[str] = []
        self.action = None
        self.action_result = None
        self.action_result_message = None
        self.action_result_data = None
        self.context_logs: List[LogMessage] = []
        self.context_processes: List[Process] = []
        self.context_flows: List[NetworkFlow] = []
        self.context_threat_intel: List[ContextThreatIntel] = []
        self.aggregated_context_logs: DefaultDict = DefaultDict(str)
        self.aggregated_context_processes: dict = {}
        self.aggregated_context_flows: dict = {}
        self.aggregated_context_threat_intel: dict = {}
        self.uuid = uuid.uuid4()

    def __dict__(self):
        """Returns the object as a dictionary."""
        dict_ = {
            "detections": self.detections,
            "playbooks": self.playbooks,
            "action": self.action,
            "action_result": self.action_result,
            "action_result_message": self.action_result_message,
            "action_result_data": self.action_result_data,
            "context_logs": self.context_logs,
            "context_processes": self.context_processes,
            "context_flows": self.context_flows,
            "context_threat_intel": self.context_threat_intel,
            "aggregated_context_logs": self.aggregated_context_logs,
            "aggregated_context_processes": self.aggregated_context_processes,
            "aggregated_context_flows": self.aggregated_context_flows,
            "aggregated_context_threat_intel": self.aggregated_context_threat_intel,
        }
        return dict_

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    def add_context_log(self, context_log: LogMessage, max_logs: int = 1000):
        """Adds a context log to the report."""
        mlog = logging_helper.Log("lib.class_helper")

        if len(self.context_logs) >= max_logs:
            mlog.warning("Reached maximum number of context logs (" + str(max_logs) + "). Skipping context log.")
            return
        self.context_logs.append(context_log)

        self.aggregated_context_logs = pd.DataFrame(self.context_logs).groupby(["source", "log_message"]).agg({"timestamp": "max"}).reset_index()
        mlog.debug("Aggregated context logs: " + json.dumps(self.aggregated_context_logs, indent=4, sort_keys=False, default=str))

    def get_title(self):
        """Returns the title of the report."""
        return self.detections[0].name  # TODO: Make this more sophisticated


class Context:
    """This class provides a context for a detection. It has three main category types: "SIEM", "ThreatIntel" and "ITSM".
    The SIEM  category type is used for context from the SIEM. It has three sub-categories: 'logs', 'Flows' and 'Processes'.  The ThreatIntel category type is used for context from
    threat intelligence sources. The ITSM category type is used for context from ITSM sources.

    Attributes:
        category (str): The category of the context (one of SIEM or ThreatIntel or ITSM)
        raw (List[str]): The raw data of a context

    Methods:
        __init__(self, category: str, sub_category: str, data: List[str]): Initializes a new Context object.
        __str__(self): Returns the string representation of the object.
    """

    def __init__(self, category):
        if category not in ["SIEM", "ThreatIntel", "ITSM"]:
            raise ValueError("Invalid category for creating context: " + category)
        self.category = category
        self.raw = {}

    def __str__(self):
        """Returns the string representation of the object."""
        return json.dumps(del_none_from_dict(self.__dict__()), indent=4, sort_keys=False, default=str)

    # Getter and setter;

    # ...


def main():
    pass


if __name__ == "__main__":
    main()
