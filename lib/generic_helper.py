# Z-SOAR
# Created by: Martin Offermann
# This module is a helper module that provides multiple generic funtions that can be used all over Z-SOAR. 
# These functions are not integration specific. For integration specific functions, please use the playbook building blocks (BB) in the playbooks folder.

import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
from lib.class_helper import del_none_from_dict

import json
from functools import reduce
import pandas as pd
import base64

mlog = logging_helper.Log("lib.generic_helper")

#

def dict_get(dictionary, keys, default=None):
    """Gets a value from a nested dictionary.

    Args:
        dictionary (dict): The dictionary to get the value from
        keys (str): The keys to get the value from
        default (any): The default value to return if the key does not exist

    Returns:
        any: The value of the key or the default value
    """
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, dict) else default,
        keys.split("."),
        dictionary,
    )

def add_to_cache(integration, category, key, value):
    """
    Adds a value to the cache of a specific integration
    
    :param integration: The integration to add the value to
    :param category: The category to add the value to
    :param key: The key to add the value for. If key is "LIST", the value will be treated as a list item and appended to the list.
    :param value: The value to add to the cache
    
    :return: None
    """
    try:
        config_all = config_helper.Config().cfg
        if config_all["cache"]["file"]["enabled"]:
            mlog.debug("add_to_cache() - Cache is enabled, saving value '" + str(value) + "' to cache. Category: '" + category + "' with key: '"+key+"' in integration: " + integration)
            cache_file = config_all["cache"]["file"]["path"]
            with open(cache_file, "r") as f:
                cache = json.load(f)

            if key == "LIST":
                mlog.debug("add_to_cache() - Key is 'LIST' literal, appending value to list")
                try:
                    if  value in cache[integration][category]:
                        mlog.debug("add_to_cache() - Value '" + str(value) + "' already exists in cache, skipping")
                        return
                    cache[integration][category].append(value)
                except KeyError:
                    if integration not in cache:
                        cache[integration] = {}
                    if category not in cache[integration]:
                        cache[integration][category] = []

                    cache[integration][category].append(value)
            else:
                try:
                    cache[integration][category][key] = value
                except KeyError:
                    if integration not in cache:
                        cache[integration] = {}
                    if category not in cache[integration]:
                        cache[integration][category] = {}

                    cache[integration][category][key] = value

            with open(cache_file, "w") as f:
                json.dump(cache, f)
            mlog.info("add_to_cache() - Value '" + str(value) + "' saved to cache. Category: '" + category + "' with key: '"+key+"' in integration: " + integration)
    except Exception as e:
        mlog.warning("add_to_cache() - Error adding value to cache: " + str(e))


def get_from_cache(integration, category, key="LIST"):
    """
    Gets a value from the cache of a specific integration
    
    :param integration: The integration to get the value from
    :param category: The category to get the value from
    :param key: The key to get the value for. If key is "LIST", the value will be treated as a list and returned.
    
    :return: The value from the cache
    """
    try:
        config_all = config_helper.Config().cfg
        if config_all["cache"]["file"]["enabled"]:
            mlog.debug("get_from_cache() - Cache is enabled, checking cache for category '" + category + "' with key: '"+str(key)+"' in integration: " + integration)
            
            # Load cahceh file to variable
            cache_file = config_all["cache"]["file"]["path"]
            mlog.debug("get_from_cache() - Loading cache file: " + cache_file)
            with open(cache_file, "r") as f:
                cache = json.load(f)
            
            # Check if category just stores a list
            if key == "LIST":
                mlog.debug("get_from_cache() - Category stores a list, returning list")
                try:
                    return cache[integration][category]
                except KeyError:
                    mlog.debug("get_from_cache() - Category does not exist in cache")
                    return None
            
            # Check if entity is in cache
            entity = dict_get(cache[integration][category], str(key))
            if entity:
                mlog.debug("get_from_cache() - Found entity in cache")
                return entity
            else:
                mlog.debug("get_from_cache() - Entity not found in cache")
                return None
    except Exception as e:
        mlog.warning("get_from_cache() - Error getting value from cache: " + str(e))
        return None

def format_results(events, format, group_by="uuid"):
    if events is None or len(events) == 0:
        return "~ No results found ~"
    
    dict_events = []

    # Removing fields that are unnecessary for the table view
    for event in events:
        if event is None or type(event) is int:
            continue
        if type(event) is list:
            event = event[0]
            mlog.warning("format_results() - 'Event' is a list, taking first item")

        event = event.__dict__()
        if "uuid" in event:
            del event["uuid"]
        if "process_parent" in event:
            del event["process_parent"]
        if "process_flow" in event:
            del event["process_flow"]
        if "process_http" in event:
            del event["process_http"]
        if "process_parent_start_time" in event:
            del event["process_parent_start_time"]
        if "process_sha256" in event:
            del event["process_sha256"]
        if "process_sha1" in event:
            del event["process_sha1"]
        if "parent_process_arguments" in event:
            del event["parent_process_arguments"]
        if "process_modules" in event:
            del event["process_modules"]
        if "process_arguments" in event:
            del event["process_arguments"]
        if "process_children" in event:
            del event["process_children"]
        if "related_detection_uuids" in event:
            del event["related_detection_uuids"]
        if "process_uuid" in event:
            del event["process_uuid"]
        if "related_detection_uuid" in event:
            del event["related_detection_uuid"]

        if "process_id" in event:
            if type(event["process_id"]) is not int: # If a UUID == process_id, limit it to not be too long in the table
                event["process_id"] = event["process_id"][:5]

        # Try to expand some fields
        try:
            if "destination_location" in event:
                loc = event["destination_location"]
                del event["destination_location"]

                if loc is not None and loc != "None":
                    loc = json.loads(loc)
                    country = dict_get(loc, "country")
                    if country is not None:
                        event["destination_location_country"] = country

                    city = dict_get(loc, "city")
                    if city is not None:
                        event["destination_location_city"] = city

                    org = dict_get(loc, "org")
                    if org is not None:
                        event["destination_location_org"] = org

            if "dns_query" in event:
                dns_query = event["dns_query"]
                del event["dns_query"]

                if dns_query is not None and dns_query != "None":
                    dns_query = json.loads(dns_query)

                    dns_query = dict_get(dns_query, "query")
                    if dns_query is not None:
                        event["dns_query"] = dns_query

                    dns_query_response = dict_get(dns_query, "query_response")
                    if dns_query_response is not None:
                        event["dns_response"] = dns_query_response

            if "process_signature" in event:
                signature = event["process_signature"]
                del event["process_signature"]

                if signature is not None and signature != "None":
                    signature = json.loads(signature)

                    issuer = dict_get(signature, "issuer")
                    if issuer is not None:
                        event["process_signature_issuer"] = issuer
                    
                    event["process_signature_trusted"] = dict_get(signature, "is_trusted")
                        
        except Exception as e:
            mlog.warning("format_results() - Error expanding fields: " + str(e))
        

        event = del_none_from_dict(event)
        dict_events.append(event)

    #events = [del_none_from_dict(event.__dict__()) for event in events]

    if format in ("html", "markdown"):
        data = pd.DataFrame(data=dict_events)
        data = data.groupby([group_by]).agg(lambda x: x.tolist())
        data.dropna(axis=1, how="all", inplace=True)

        if format == "html":
            tmp = data.to_html(index=False, classes=None)
            return tmp.replace(' class="dataframe"', "")
        elif format == "markdown":
            return data.to_markdown(index="false")
    elif format == "json":
        return json.dumps(events, ensure_ascii=False, sort_keys=False)
