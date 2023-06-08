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

def deep_get(dictionary, keys, default=None):
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
            entity = deep_get(cache[integration][category], str(key))
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


def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False
