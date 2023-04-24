# Z-SOAR
# Created by: Martin Offermann
# This helper module is used to provide a valid config object. To do that it will load the zsoar_config YAML file in the configs directory.
# It will also provide an explicit function to check if the config file is valid and a helper fumction for setup questions.

import os
import yaml
import sys
import re
import getpass

LOG_LEVEL = "CRITICAL"  # The log level of this config loader. This is not set by the config to prevent sending no message at all if the config file, which stores the log_lvel istself is not valid.
FILE_PATH = "configs/zsoar_config.yml"


class Config:
    """The Config() class is used to provide a valid config object. To do that it will load the zsoar_config YAML file in the configs directory.
    It will also provide an explicit function to check if the config file is valid.

    Args:
        None

    Returns:
        A config object
    """

    # Get the logger

    def __init__(self):
        import lib.logging_helper as logging_helper

        mlog = logging_helper.Log("lib.config_helper", log_level=LOG_LEVEL)

        # Check if the config file exists
        if not os.path.isfile(FILE_PATH):
            print("[CRITICAL] The config file does not exist.")
            raise TypeError("The config file does not exist.")

        # Load the config file
        with open(FILE_PATH, "r") as ymlfile:
            self.cfg = yaml.safe_load(ymlfile)

        if self.cfg is None:
            print("[CRITICAL] The config file is empty.")
            raise TypeError("The config file is empty.")

        if type(self.cfg) != dict:
            print("[CRITICAL] The config file is not valid. Please check the config file and try again.")
            raise TypeError("The config file is not valid.")

        # Check if an entry in the config file is supposed to be an environment variable
        try:
            if self.cfg["setup"]["load_enviroment_variables"] == True:
                replace_env_vars(cfg=self.cfg, mlog=mlog)
            else:
                mlog.debug(message="Not loading environment variables from config file.")
        except KeyError:
            mlog.warning(message="Did not load environment variables from config file. Setting wheither to enable it not found.")

        try:
            mlog.set_level(self.cfg["logging"]["log_level_stdout"])
        except:
            print("[CRITICAL] Could not load config file: logging_level_stdout not defined. Please check the config file and try again.")
            raise TypeError("The config file is not valid.")

        # Check if the config file is valid
        if not check_config(self.cfg, mlog):
            mlog.critical("The config file is not valid. Please check the config file and try again.")
            raise TypeError("The config file is not valid.")
        else:
            return None


def replace_env_vars(cfg, mlog):
    try:
        for key, value in cfg.items():
            if isinstance(value, dict):
                replace_env_vars(value, mlog)
            elif isinstance(value, str) and value.startswith("$"):
                env_var_name = value[1:]
                env_var_value = os.environ.get(env_var_name)
                if env_var_value is not None:
                    if env_var_value.isdigit():
                        cfg[key] = int(env_var_value)
                    elif env_var_value.lower() == "true":
                        cfg[key] = True
                    elif env_var_value.lower() == "false":
                        cfg[key] = False
                    else:
                        cfg[key] = env_var_value
                else:
                    mlog.critical(
                        "The environment variable '"
                        + value[1:]
                        + "' used in the config '"
                        + key
                        + "' is not set. Export it (or remove the '$' before the value) and try again."
                    )
                    raise ValueError("The environment variable {} is not set.".format(value[1:]))
    except Exception as e:
        if e.__class__.__name__ == "ValueError":
            raise
        mlog.error(message="Could not load environment variables from config file: " + str(e))
        raise Exception("Could not load environment variables from config file: " + str(e))


def check_config_log_level(log_level, mlog):
    """The check_config_log_level() function is used to check if the log level is valid.

    Args:
        cfg (dict): The config object
        mlog (Log): The logger object

    Returns:
        True if the log level is valid, False if not
    """
    try:
        if type(log_level) != str or log_level.upper() not in [
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
            "NONE",
        ]:
            mlog.critical(
                f"Could not load config file: {log_level} not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'none']. Please check the config file and try again."
            )
            return False
        else:
            return True
    except:
        mlog.critical(f"Could not load config file: {log_level} not defined. Please check the config file and try again.")
        return False


def check_config_bool(bool_var, mlog):
    """Check if a variable is a valid boolean.

    Args:
        bool_var (bool): The variable to check

    Returns:
        True if the variable is a valid boolean, False if not
    """
    if type(bool_var) != bool or bool_var not in [
        True,
        False,
    ]:
        mlog.critical("daemon_enabled not one of [True, False]. Please check the config file.")
        return False
    return True


def check_config_int(int_var, mlog):
    """Check if a variable is a valid integer above or equal to 0.

    Args:
        int_var (int): The variable to check

    Returns:
        True if the variable is a valid integer, False if not
    """
    if type(int_var) != int or int_var < 0:
        mlog.critical("daemon_interval_min not a valid integer value. Please check the config file.")
        return False
    return True


def check_config(cfg, mlog, onload=True):
    """The check_config() function is used to check if the config file is valid.

    Args:
        cfg (dict): The config object
        mlog (Log): The logger object
        onload (bool): If the function is called on load or not (makes a difference in the log level and return value)

    Returns:
        True if the config file is valid (enough), False if not
    """
    try:
        # daemon
        if not check_config_bool(cfg["daemon"]["enabled"], mlog):
            return False

        if not check_config_int(cfg["daemon"]["interval_min"], mlog):
            return False

        # logging

        if type(cfg["logging"]["language"]) != str or cfg["logging"]["language"].lower() not in [
            "en",
            "de",
        ]:
            mlog.warning("language not one of ['en', 'de']. Please check the config file. Will assume value to be 'en'.")
            if not onload:  # Be more strict when saving TO the config file...
                return False
            cfg["logging"]["language"] = "en"  # ...If not then assume a default value

        if not check_config_log_level(cfg["logging"]["log_level_stdout"], mlog):
            return False

        if not check_config_log_level(cfg["logging"]["log_level_file"], mlog):
            return False

        if not check_config_log_level(cfg["logging"]["log_level_syslog"], mlog):
            return False

        if not check_config_bool(cfg["logging"]["split_file_on_worker_iteration"], mlog):
            return False

        if not check_config_bool(cfg["logging"]["split_file_on_startup"], mlog):
            return False

        if not check_config_bool(cfg["logging"]["split_files_by_module"], mlog):
            return False

        if not check_config_int(cfg["logging"]["log_file_rotate_size"], mlog):
            return False

        # setup

        if not check_config_int(cfg["setup"]["setup_step"], mlog):
            return False

        if not check_config_bool(cfg["setup"]["load_enviroment_variables"], mlog):
            return False

        # znuny_otrs

        # TODO: OTRS settings

        # integrations

        for integration in cfg["integrations"]:
            if not check_config_bool(cfg["integrations"][integration]["enabled"], mlog):
                return False
            mlog.debug(f"Loaded integration: {integration}")

        # cache        
        if not check_config_bool(cfg["cache"]["file"]["enabled"], mlog):
            return False
        if not check_config_int(cfg["cache"]["file"]["max_age_hours"], mlog):
            return False
        if not check_config_int(cfg["cache"]["file"]["max_size_mb"], mlog):
            return False
        # Try open the given file
        try:
            open(cfg["cache"]["file"]["path"], "a").close()
        except Exception as e:
            mlog.critical(f"Could not open cache file: {e}")
            return False
    
       # TODO Add Elasticsearch cache
    
            

    except KeyError as e:
        mlog.critical("Could not load config file: Setting not found: {}. Please check the config file and try again.".format(e))
        return False

    return True


def save_config(cfg):
    """The save_config() function is used to save/update the provided config to file.
        It will also ensure that the values of environment variables are not saved to file.

    Args:
        cfg (dict): The config object

    Returns:
        True if the config file was saved, False if not
    """

    import lib.logging_helper as logging_helper

    mlog = logging_helper.Log("lib_load_config", log_level=cfg["logging"]["log_level_stdout"])

    if not check_config(cfg, mlog, onload=False):
        mlog.warning("Could not update config file, as the provided file was invalid!")
        return False

    try:
        # We have to write to a tmp file first to not immediatly overwrite enviroment variables
        # in the current file with their respective values
        with open(FILE_PATH + ".tmp", "w") as ymlfile:
            yaml.dump(cfg, ymlfile, default_flow_style=False)
    except Exception as e:
        mlog.critical("Could not save to (temp) config file: " + str(e))
        return False

    try:
        # Check the temp file line by line if the real file line containts a '$'.
        # If it doesn't, copy line from tmp file to the real file

        # First dump the tmp file to a list
        with open(FILE_PATH + ".tmp", "r") as ymlfile:
            tmp_file = ymlfile.readlines()

        # Then dump the real file to a list
        with open(FILE_PATH, "r") as ymlfile:
            real_file = ymlfile.readlines()

        # Now compare the two lists and write the tmp file to the real file
        with open(FILE_PATH, "w") as ymlfile_write:
            for line, line_tmp in zip(real_file, tmp_file):
                if "$" not in line or "$" in line_tmp:
                    print("no $ in line. line_tmp: " + line_tmp + " line current: " + line)
                    print(line_tmp, end="", file=ymlfile_write)
                else:
                    print("found $ in line. line_tmp: " + line_tmp + " line current: " + line)
                    print(line, end="", file=ymlfile_write)

        # Delete temp file
        os.remove(FILE_PATH + ".tmp")

        return True

    except Exception as e:
        mlog.critical("Could not save to (final) config file: " + str(e))
        return False


def setup_ask(default_response, available_responses_list=[], available_responses_is_int_goe=-1, available_response_is_url=False, secret=False):
    """The setup_ask() function is used to ask the user for a config value, used for setup.

    Args:
        mlog (Log): The logger object
        default_response (str): The default response
        available_responses_list (list): A list of available responses
        available_responses_is_int_goe (int): If the available responses are integers greater or equal than this value
        available_response_is_url (bool): If the available responses are URLs
        secret (bool): If the input should be hidden

    Returns:
        The response of the user. String "Skipped" if the user skipped the question.
    """
    try:
        if (
            (type(available_responses_is_int_goe) == int and available_responses_is_int_goe > -1)
            or available_responses_list == []
            or available_response_is_url
        ):
            print("Please enter your choice or press enter for default ({}): ".format(default_response))
        else:
            print("Please enter your choice of either: [{}] or press enter for default ({}):".format(available_responses_list, default_response))

        if not secret:
            response = input()
        else:
            response = getpass.getpass()

        if response == "":
            response = default_response

        if available_responses_list != []:
            if response not in available_responses_list:
                print("Invalid response. Please try again.")
                return setup_ask(
                    default_response,
                    available_responses_list=available_responses_list,
                    available_responses_is_int_goe=available_responses_is_int_goe,
                )
            else:
                return response

        elif type(available_responses_is_int_goe) == int and available_responses_is_int_goe > -1:
            try:
                response = int(response)
            except:
                print("Invalid response. Please try again.")
                return setup_ask(
                    default_response,
                    available_responses_list=available_responses_list,
                    available_responses_is_int_goe=available_responses_is_int_goe,
                )
            else:
                if response <= available_responses_is_int_goe:
                    print("Invalid response. Please try again.")
                    return setup_ask(
                        default_response,
                        available_responses_list=available_responses_list,
                        available_responses_is_int_goe=available_responses_is_int_goe,
                    )
                else:
                    return response

        elif available_response_is_url:
            if not re.match(r"^https?:\/\/", response):
                print("Invalid response (not an URL). Please try again.")
                return setup_ask(
                    default_response,
                    available_responses_list=available_responses_list,
                    available_responses_is_int_goe=available_responses_is_int_goe,
                    available_response_is_url=available_response_is_url,
                )
            else:
                return response

        return response
    except KeyboardInterrupt:
        print("Skipping question...")
        return "Skipped"


def setup_integration(integration_name, cfg_integration, type, message, sub_config="", allow_skip=False, additional_info=""):
    """This function can be used by integrations to setup their config.

    Args:
        integration_name (str): The name of the integration
        cfg_integration (dict): The integration config
        type (str): The type of the config value [str, url, y/n, number_pos, log_level, secret]
        message (str): The message to display to the user
        sub_config (str, optional): The sub config to use (if the integration has nested configs). Defaults to "".
        allow_skip (bool, optional): If the user should be allowed to skip the question. Defaults to False.
        additional_info (str, optional): Additional info to display to the user. Defaults to "".

    Returns:
        success (bool): If the setup was successful (explicitly False if the user skipped the question)
    """
    if type not in ["str", "url", "y/n", "number_pos", "log_level", "secret"]:
        raise Exception("Invalid type provided for setup_response()")

    # Load current config
    settings = Config().cfg

    # Print message(s)
    print("")
    print("")
    print(message)
    if additional_info != "":
        print("(" + additional_info + ")")
    print("")

    # Get response
    if type == "str":
        response = setup_ask("", secret=False)

    if type == "url":
        response = setup_ask("https://localhost:9200", available_response_is_url=True)

    elif type == "y/n":
        response_yn = setup_ask("y", available_responses_list=["y", "n"])
        if response_yn == "y":
            response = True
        else:
            response = False

    elif type == "number_pos":
        response = setup_ask("1", available_responses_is_int_goe=0)

    elif type == "log_level":
        response = setup_ask("info", available_responses_list=["info", "debug", "warning", "error", "critical"])

    elif type == "secret":
        print("Do you want to save the secret as an environment variable instead of in the config file?")
        save_env = setup_ask("y", available_responses_list=["y", "n"])
        if save_env == "y":
            print("Please enter the name of the environment variable (without $ symbol):")
            env_name = setup_ask("SECRET_" + integration_name.upper())
            response = "$" + env_name

            print("Please enter the asked secret itself (see above) to store in the environment variable:")
            secret = setup_ask("", secret=True)
            os.environ[env_name] = secret  # Only the name of the env var is stored in the config file, prepended with a $ symbol
        else:
            print("Please enter the asked secret (see above) that will be saved in the config file:")
            response = setup_ask("", secret=True)

    # Save response
    try:
        if sub_config == "":
            settings["integrations"][integration_name][cfg_integration] = response
        else:
            settings["integrations"][integration_name][cfg_integration][sub_config] = response
    except KeyError:
        print("ERROR Could not save response, as the provided config was not found in the config file!")
        return False

    if save_config(settings):
        print("Config saved successfully.")
        return True
    else:
        print("ERROR Could not save config file.")
        return False


def main():
    # cfg = Config()
    # print(cfg.cfg)
    pass


if __name__ == "__main__":
    main()
