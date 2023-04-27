# Z-SOAR
# Created by: Martin Offermann
# This module is a helper module that provides multiple generic funtions that can be used all over Z-SOAR. 
# These functions are not integration specific. For integration specific functions, please use the playbook building blocks (BB) in the playbooks folder.

import lib.logging_helper as logging_helper
import lib.config_helper as config_helper
import json
from functools import reduce

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


def get_from_cache(integration, category, key):
    """
    Gets a value from the cache of a specific integration
    
    :param integration: The integration to get the value from
    :param category: The category to get the value from
    :param key: The key to get the value for
    
    :return: The value from the cache
    """
    try:
        config_all = config_helper.Config().cfg
        if config_all["cache"]["file"]["enabled"]:
            mlog.debug("get_from_cache() - Cache is enabled, checking cache for category '" + category + "' with key: '"+key+"' in integration: " + integration)
            
            # Load cahceh file to variable
            cache_file = config_all["cache"]["file"]["path"]
            mlog.debug("get_from_cache() - Loading cache file: " + cache_file)
            with open(cache_file, "r") as f:
                cache = json.load(f)
            
            # Check if entity is in cache
            entity = deep_get(cache[integration][category], key)
            if entity:
                mlog.debug("get_from_cache() - Found entity in cache")
                return entity
            else:
                mlog.debug("get_from_cache() - Entity not found in cache")
                return None
    except Exception as e:
        mlog.warning("get_from_cache() - Error getting value from cache: " + str(e))
        return None
