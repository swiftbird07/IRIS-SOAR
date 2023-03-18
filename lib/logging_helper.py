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
        log_level_to_file="none",
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

            # Core modules will use the logging settings from the config file
            if "zsoar" in module_name and "test" not in module_name:
                import lib.config_helper as config_helper

                # Load the settings
                settings = config_helper.Config().cfg

                # Override default paramaters if set in config:
                log_level_to_file = settings["logging"]["log_level_to_file"]
                log_level_stdout = settings["logging"]["log_level_stdout"]

            if "none" not in log_level_to_file:
                if settings["logging"]["split_files_by_module"]:
                    path = "logs/" + module_name + ".log"
                else:
                    path = "logs/zsoar.log"
                os.makedirs(
                    os.path.dirname(path), exist_ok=True
                )  # According to documentation of logger, this is not needed, but that is not true
                handlerFile = logging.FileHandler(path)
                handlerFile.setLevel(log_level_to_file.upper())
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


if __name__ == "__main__":
    pass
