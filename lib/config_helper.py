# Z-SOAR
# Created by: Martin Offermann
# This helper module is used to provide a valid config object. To do that it will load the zsoar_config YAML file in the configs directory.
# It will also provide an explicit function to check if the config file is valid and a helper fumction for setup questions.

import os
import yaml
import sys

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

        mlog = logging_helper.Log("lib_load_config", log_level=LOG_LEVEL)

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
            print(
                "[CRITICAL] The config file is not valid. Please check the config file and try again."
            )
            raise TypeError("The config file is not valid.")

        try:
            mlog.set_level(self.cfg["logging"]["log_level_stdout"])
        except:
            print(
                "[CRITICAL] Could not load config file: logging_level_stdout not defined. Please check the config file and try again."
            )
            raise TypeError("The config file is not valid.")

        # Check if the config file is valid
        if not check_config(self.cfg, mlog):
            mlog.critical(
                "The config file is not valid. Please check the config file and try again."
            )
            raise TypeError("The config file is not valid.")
        else:
            return None


def check_config(cfg, mlog, onload=True):
    """The check_config() function is used to check if the config file is valid.

    Args:
        cfg (dict): The config object
        mlog (Log): The logger object
        onload (bool): If the function is called on load or not (makes a difference in the log level and return value)

    Returns:
        True if the config file is valid (enough), False if not
    """

    if type(cfg["logging"]["log_level_stdout"]) != str or cfg["logging"][
        "log_level_stdout"
    ].upper() not in [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
        "NONE",
    ]:
        if onload:
            mlog.critical(
                "Could not load config file: logging_level_stdout not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'none']. Please check the config file and try again."
            )
        else:
            mlog.warning(
                "Could not load config file: logging_level_stdout not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'none']. Please check the config file and try again."
            )
        return False

    if type(cfg["logging"]["log_level_to_file"]) != str or cfg["logging"][
        "log_level_to_file"
    ].upper() not in [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
        "NONE",
    ]:
        if onload:
            mlog.critical(
                "Could not load config file: logging_level_to_file not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'none']. Please check the config file and try again."
            )
        else:
            mlog.warning(
                "Could not load config file: logging_level_to_file not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'none']. Please check the config file and try again."
            )

        return False

    if type(cfg["logging"]["language"]) != str or cfg["logging"]["language"].lower() not in [
        "en",
        "de",
    ]:
        mlog.warning(
            "language not one of ['en', 'de']. Please check the config file. Will assume value to be 'en'."
        )
        if not onload:  # Be more strict when saving TO the config file...
            return False
        cfg["logging"]["language"] = "en"  # ...If not then assume a default value

    if type(cfg["logging"]["split_file_on_worker_iteration"]) != bool or cfg["logging"][
        "split_file_on_worker_iteration"
    ] not in [True, False]:
        mlog.warning(
            "split_file_on_worker_iteration not one of [True, False]. Please check the config file. Will assume value to be False."
        )
        if not onload:
            return False
        cfg["logging"]["split_file_on_worker_iteration"] = False

    if type(cfg["logging"]["split_file_on_startup"]) != bool or cfg["logging"][
        "split_file_on_startup"
    ] not in [True, False]:
        mlog.warning(
            "split_file_on_startup not one of [True, False]. Please check the config file. Will assume value to be False."
        )
        if not onload:
            return False
        cfg["logging"]["split_file_on_startup"] = False

    if type(cfg["daemon"]["enabled"]) != bool or cfg["daemon"]["enabled"] not in [
        True,
        False,
    ]:
        mlog.warning(
            "daemon_enabled not one of [True, False]. Please check the config file. Will assume value to be False."
        )
        if not onload:
            return False
        cfg["daemon"]["enabled"] = False

    if type(cfg["daemon"]["interval_min"]) != int or cfg["daemon"]["interval_min"] < 0:
        mlog.warning(
            "daemon_interval_min not a valid integer value. Please check the config file. Will assume value to be 5 minutes."
        )
        if not onload:
            return False
        cfg["daemon"]["interval_min"] = 5

    print(type(cfg["setup"]["setup_step"]))
    if type(cfg["setup"]["setup_step"]) != int or cfg["setup"]["setup_step"] < 0:
        mlog.warning(
            "setup_step not a valid integer value. Please check the config file. Will assume value to be 0 (new setup)."
        )
        if not onload:
            return False
        cfg["setup"]["setup_step"] = 0

    if type(cfg["logging"]["log_level_syslog"]) != str or cfg["logging"][
        "log_level_syslog"
    ].upper() not in [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
        "NONE",
    ]:
        mlog.warning(
            "log_level_syslog not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'none']. Please check the config file. Will assume value to be 'none'."
        )
        if not onload:
            return False
        cfg["logging"]["log_level_syslog"] = "none"

    if (
        type(cfg["logging"]["log_file_rotate_size"]) != int
        or cfg["logging"]["log_file_rotate_size"] < 0
    ):
        mlog.warning(
            "log_file_rotate_size not a valid integer value. Please check the config file. Will assume value to be 0 (disabled)."
        )
        if not onload:
            return False
        cfg["logging"]["log_file_rotate_size"] = 0

    return True  # Only warnings


def save_config(cfg):
    """The save_config() function is used to save/update the provided config to file.

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
        with open(FILE_PATH, "w") as ymlfile:
            yaml.dump(cfg, ymlfile, default_flow_style=False)
    except:
        mlog.critical("Could not save config file.")
        return False
    else:
        return True


def setup_ask(default_response, available_responses_list=[], available_responses_is_int_goe=-1):
    """The setup_ask() function is used to ask the user for a config value, used for setup.

    Args:
        mlog (Log): The logger object
        default_response (str): The default response
        available_responses_list (list): A list of available responses
        available_responses_is_int_goe (int): If the available responses are integers greater or equal than this value

    Returns:
        The response of the user. String "Skipped" if the user skipped the question.
    """
    try:
        if type(available_responses_is_int_goe) == int and available_responses_is_int_goe > -1:
            print(
                "Please enter your choice or press enter for default ({}): ".format(
                    default_response
                )
            )
        else:
            print(
                "Please enter your choice of either: [{}] or press enter for default ({}):".format(
                    default_response, available_responses_list
                )
            )

        response = input()

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

        return response
    except KeyboardInterrupt:
        print("Skipping question...")
        return "Skipped"


def main():
    cfg = Config()
    # print(cfg.cfg)


if __name__ == "__main__":
    main()
