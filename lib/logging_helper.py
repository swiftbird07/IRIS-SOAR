# Z-SOAR
# Created by: Martin Offermann
# This helper module is used to provide a Log() object that uses the python 'logger', but adds additional info, like the module name.

import sys
import logging
import os

TEST_CALL = True  # Stays True if the script is called by the test script


class Log:
    """The Log class is used to provide a Log() object that uses the python 'logger', but adds additional info, like the module name.

    Args:
        None

    Returns:
        None
    """

    def __init__(
        self,
        module_name,
        log_level="none",
        log_level_file="none",
        log_level_stdout="INFO",
    ):
        """Initializes the Log() object.

        Args:
            module_name (str): The name of the module

        Returns:
            A logger object
        """
        try:
            TEST_CALL = False
            self.logger = logging.getLogger(module_name)
            self.logger.setLevel(10)
            self.logger.propagate = False

            # Create a logging format
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

            if "lib.config_helper" not in module_name:  # Avoid circular import from config_helper
                import lib.config_helper as config_helper

                # Load the settings
                settings = config_helper.Config().cfg

                # Override default paramaters if set in config:
                if log_level_file == "none" and log_level == "none":
                    log_level_file = settings["logging"]["log_level_file"]
                if log_level_stdout == "none" and log_level == "none":
                    log_level_stdout = settings["logging"]["log_level_stdout"]

            if "none" not in log_level_file:
                if settings["logging"]["split_files_by_module"]:
                    path = "logs/" + module_name + ".log"
                else:
                    path = "logs/zsoar.log"
                os.makedirs(os.path.dirname(path), exist_ok=True)  # According to documentation of logger, this is not needed, but that is not true
                handlerFile = logging.FileHandler(path)
                handlerFile.setLevel(log_level_file.upper())
                handlerFile.setFormatter(formatter)
                self.logger.addHandler(handlerFile)

            if ("none" not in log_level_stdout) or ("none" not in log_level):
                handlerStream = logging.StreamHandler()
                try:
                    handlerStream.setLevel(level=log_level_stdout.upper())
                except AttributeError:
                    handlerStream.setLevel(log_level.upper())

                handlerStream.setFormatter(formatter)
                self.logger.addHandler(handlerStream)
        except Exception as e:
            print(f"[CRITICAL] The logger object for {module_name} could not be initialized.")
            raise (e)

        return None

    def set_level(self, level):
        """Change the logging level of the logger object and also for all its handlers."""
        self.logger.setLevel(level.upper())

        # We have to set all handlers to the same level as well (thanks to Martijn Pieters @ https://stackoverflow.com/a/38496484)
        for handler in self.logger.handlers:
            handler.setLevel(level.upper())

    def debug(self, message):
        """Logs a debug message.

        Args:
            message (str): The message

        Returns:
            None
        """
        self.logger.debug(message)

    def info(self, message):
        """Logs an info message.

        Args:
            message (str): The message

        Returns:
            None
        """
        self.logger.info(message)

    def warning(self, message):
        """Logs a warning message.

        Args:
            message (str): The message

        Returns:
            None
        """
        self.logger.warning(message)

    def error(self, message):
        """Logs an error message.

        Args:
            message (str): The message

        Returns:
            None
        """
        self.logger.error(message)

    def critical(self, message):
        """Logs a critical message.

        Args:
            message (str): The message

        Returns:
            None
        """
        self.logger.critical(message)


def update_audit_log(detection_uuid, new_action, logger=None):
    """Updates the audit log file with the given audit_log.
       If an audit log with the same playbook and stage already exists, it will be overwritten.
       
    Args:
        detection_uuid (str): The detection uuid
        audit_log (dict): The audit log
        logger (Log): The logger object (optional) Set if the audit shall be logged to the normal log file as well
        
    Returns:
        None
    """
    import json
    path = "logs/audit.log"
    mlog = Log("logging_helper")

    # Load the audit log
    try:
        with open(path, "r") as f:
            audit_log_file = json.load(f)
    except FileNotFoundError:
        mlog.warning(f"Could not find audit log file at {path}. Creating a new one.")
        audit_log_file = {}
    except Exception as e:
        if e is not FileNotFoundError:
            mlog.critical(f"Could not load audit log file at {path}. Error: {e}")
            return

    # Get the audit log for given detection_uuid
    try:
        al_detection = audit_log_file[str(detection_uuid)]
        mlog.debug(f"Found audit log for detection_uuid {detection_uuid}: {al_detection}")
    except KeyError:
        mlog.info(f"Could not find audit log for detection_uuid {detection_uuid}. Creating a new one.")
        al_detection = []
    
    # Update the audit log but check if playbook and stage already exists
    is_update = False
    if al_detection != []:
        for element in al_detection:
            element_dict = json.loads(element)
            if element_dict["playbook"] == new_action.playbook and element_dict["stage"] == new_action.stage:
                mlog.debug(f"Found existing audit log for playbook {new_action.playbook} and stage {new_action.stage}. Overwriting it.")
                is_update = True
                al_detection.remove(element)
                break

    # Add the new audit log
    str_new_action = str(new_action)
    al_detection.append(str_new_action)
    audit_log_file[str(detection_uuid)] = al_detection

    # Save the audit log
    try:
        with open(path, "w") as f:
            json.dump(audit_log_file, f, indent=4)
    except Exception as e:
        mlog.critical(f"Could not save audit log file at {path}. Error: {e}")

    if logger is not None:
        if type(logger) is Log:
            if is_update:
                logger.info(f"[AUDIT_UPDATE] DetectionReport '{detection_uuid}' : {str_new_action}") # TODO: Fix this not working
            else:
                logger.info(f"[AUDIT] DetectionReport '{detection_uuid}' : {str_new_action}")
        else:
            mlog.error(f"Given logger object is not of type Log. Could not log to logger.")
    else:
        mlog.debug(f"No logger object given. Not logging to logger.")
    return
    

if __name__ == "__main__":
    pass
