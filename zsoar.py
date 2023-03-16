# Z-SOAR
# Created by: Martin Offermann
# This module is the user interactive start point for the Z-SOAR project.
# It will load the prvided arguments and either start the setup mode or start/stop/restart the main zsoar_worker.py or delegate this job to the daemon if enabled.

import sys
import os
import argparse

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import zsoar_daemon as zsoar_daemon

TEST_CALL = True  # Stays True if the script is called by the test script


def add_arguments():
    """Parses the provided arguments.

    Args:
        args (list): The arguments

    Returns:
        parser (argparse.ArgumentParser): The parser
    """
    parser = argparse.ArgumentParser(description="Z-SOAR - Modular SOAR for Znuny/OTRS")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--setup", action="store_true", help="Install or Configure Z-SOAR")
    parser.add_argument("--start", action="store_true", help="Start Z-SOAR")
    parser.add_argument("--stop", action="store_true", help="Stop Z-SOAR")
    parser.add_argument("--restart", action="store_true", help="Restart Z-SOAR")
    parser.add_argument("--status", action="store_true", help="Show the status of Z-SOAR")

    return parser


def startup(mlog):
    """Starts the main loop or the daemon depending on the settings.

    Args:
        mlog (logging_helper.Log): The logger

    Returns:
        None

    Raises:
        None
    """

    # Load the settings
    settings = config_helper.Config().cfg  #

    # Check if the daemon is enabled
    if settings["daemon"]["enabled"]:
        # Start the daemon
        mlog.info("Starting the daemon")
        if os.system("python3 lib/daemon.py"):
            mlog.critical("Could not start the daemon: System call failed.")
            raise SystemExit(1)
    else:
        # Start the main loop
        mlog.info("Daemon disabled. Starting the main loop directly.")
        if os.system("python3 zsoar_worker.py"):
            mlog.critical("Could not start the worker: System call failed.")
            raise SystemExit(1)


def stop(mlog):
    """Stops the the daemon process.

    Args:
        mlog (logging_helper.Log): The logger

    Returns:
        None

    Raises:
        None
    """
    mlog.info("Stopping Z-SOAR...")
    import subprocess as subp

    daemon_pids = list(
        map(int, subp.check_output(["pgrep", "-f", "python3 zsoar_daemon.py"]).split())
    )
    for daemon_pid in daemon_pids:
        os.kill(daemon_pid, 15)
    mlog.info("Z-SOAR stopped")


def setup(step=0, continue_steps=True):
    """Starts the setup mode.

    Args:
        None

    Returns:
        None
    """
    settings = config_helper.Config().cfg
    from lib.config_helper import setup_ask

    if settings["setup"]["setup_step"] == 0:
        # Start the setup
        print("Welcome to the Z-SOAR setup!")
        print("This setup will guide you through the installation and configuration of Z-SOAR.")
        print("Please note that this setup is not yet finished and will be extended in the future.")
        print("If you want to skip the setup, you can edit the config file manually.")
        print(
            "The config file is located at: " + os.path.join(os.getcwd(), "config", "zsoar.cfg.yml")
        )
        print(
            "You can also continue the setup by running the setup mode again. To start from the beginning, delete the config file."
        )
        print("")
        print("Do you want to start the setup now?")
        response = setup_ask("n", available_responses_list=["y", "n"])
        if response == "y":
            settings["setup"]["setup_step"] = 1
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(1)

    elif settings["setup"]["setup_step"] == 1 or step == 1:
        # Check if the daemon should be enabled
        print("")
        print("Do you want to enable the daemon?")
        response = setup_ask("n", available_responses_list=["y", "n"])
        if response == "y":
            settings["daemon"]["enabled"] = True
        elif response == "n":
            settings["daemon"]["enabled"] = False
        settings["setup"]["setup_step"] = 2
        config_helper.save_config(settings)
        if not continue_steps:
            return
        setup(2)

    elif settings["setup"]["setup_step"] == 2 or step == 2:
        # Ask for the interval of the daemon
        print("")
        print(
            "Please enter the minimum interval between Z-SOAR worker processes in minutes used by the daemon (0 to immediatly start the next worker process if the last one exited):"
        )
        interval = setup_ask(5, available_responses_is_int_goe=0)
        if type(interval) == int and interval >= 0:
            settings["daemon"]["interval"] = interval
            settings["setup"]["setup_step"] = 3
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(3)

    elif settings["setup"]["setup_step"] == 3 or step == 3:
        # Ask for the logging lanuguage
        print("")
        print("Please enter the language of the log messages (NOT YET IMPLEMENTED):")
        lang = setup_ask("en", available_responses_list=["en"])  # TODO: Add more languages
        if lang == "en":
            settings["logging"]["language"] = "en"
            settings["setup"]["setup_step"] = 4
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(4)

    elif settings["setup"]["setup_step"] == 4 or step == 4:
        # Ask for logging level for stdout
        print("")
        print("Please enter the logging level for the console output:")
        level = setup_ask(
            "info",
            available_responses_list=["debug", "info", "warning", "error", "critical", "none"],
        )
        if level != "Skipped":
            settings["logging"]["log_level_stdout"] = level
            settings["setup"]["setup_step"] = 5
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(5)

    elif settings["setup"]["setup_step"] == 5 or step == 5:
        # Ask for logging level for file logging
        print("")
        print("Please enter the logging level for the log file:")
        level = setup_ask(
            "warning",
            available_responses_list=["debug", "info", "warning", "error", "critical", "none"],
        )
        if level != "Skipped":
            settings["logging"]["log_level_file"] = level
            settings["setup"]["setup_step"] = 6
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(6)

    elif settings["setup"]["setup_step"] == 6 or step == 6:
        # Ask if log files should be rotated
        print("")
        print(
            "If you want to rotate the log files, please enter the maximum size of the log files in KB (0 to disable log file rotation):"
        )
        size = setup_ask(0, available_responses_is_int_goe=0)
        if type(size) == int and size > 0:
            settings["logging"]["log_file_rotate_size"] = size
            settings["setup"]["setup_step"] = 7
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(7)

    elif settings["setup"]["setup_step"] == 7 or step == 7:
        # Ask for logging level for syslog logging
        print("")
        print("Please enter the logging level for the syslog (NOT YET IMPLEMENTED):")
        level = setup_ask(
            "none",
            available_responses_list=["debug", "info", "warning", "error", "critical", "none"],
        )
        if level != "Skipped":
            settings["logging"]["log_level_syslog"] = level  # TODO: Implement syslog logging
            settings["setup"]["setup_step"] = 8
            config_helper.save_config(settings)
            if not continue_steps:
                return
            setup(8)

    elif settings["setup"]["setup_step"] == 8 or step == 8:
        # Ask if log files should be split for each worker iteration
        print("")
        print("Do you want to split the log files for each worker iteration? (not reccomened)")
        response = setup_ask("n", available_responses_list=["y", "n"])
        if response == "y":
            settings["logging"]["log_file_split"] = True
        elif response == "n":
            settings["logging"]["log_file_split"] = False
        settings["setup"]["setup_step"] = 9
        config_helper.save_config(settings)
        if not continue_steps:
            return
        setup(9)

    elif settings["setup"]["setup_step"] == 9 or step == 9:
        # Ask if log files should be split for each start of the daemon
        print("")
        print("Do you want to split the log files for each start of the daemon?")
        response = setup_ask("y", available_responses_list=["y", "n"])
        if response == "y":
            settings["logging"]["log_file_split_start"] = True
        elif response == "n":
            settings["logging"]["log_file_split_start"] = False
        settings["setup"]["setup_step"] = 10
        config_helper.save_config(settings)
        if not continue_steps:
            return
        setup(10)

    elif settings["setup"]["setup_step"] == 10 or step == 10:
        print("")
        print("Setup finished. You can now start the daemon with the command 'zsoar.py --start'.")
        settings["setup"]["setup_step"] = 0
        config_helper.save_config(settings)
        if not TEST_CALL and not continue_steps:
            sys.exit(0)

    # TODO: Add Znuny/OTRS connection setup

    print("Setup stopped. Please run the setup again to continue.")


#
# znuny_otrs:
#    hostname:
#    web_service_name:
#    api_customer_user:
#    api_customer_password:

# ...


def main():
    """The main function of the zsoar.py script.

    Args:
        None

    Returns:
        None
    """

    parser = add_arguments()
    args = parser.parse_args()

    # Create the module's logger
    mlog = logging_helper.Log("zsoar")

    # Check if at least one argument is provided:
    if type(args) == argparse.Namespace:
        print("No mode selected. Please use --help to see the available modes.")
        if not TEST_CALL:
            sys.exit(0)

    # Check if the version mode is enabled:
    if parser.parse_args().version:
        print("Z-SOAR Version 0.0.1 (alpha)")
        if not TEST_CALL:
            sys.exit(0)

    # Check if debug mode is enabled:
    if parser.parse_args().debug:
        os.environ["DEBUG"] = "True"
        DEBUG = True
        mlog.info("* Debug mode is enabled *")
        mlog.set_level("debug")
    else:
        DEBUG = False

    # Check if the setup mode is enabled:
    if parser.parse_args().setup:
        mlog.info("Starting the setup...")
        setup(mlog)

    # Check if the start mode is enabled:
    if parser.parse_args().start:
        mlog.info("Starting Z-SOAR")
        startup(mlog, DEBUG)
        if not TEST_CALL:
            sys.exit(0)

    # Check if the stop mode is enabled:
    if parser.parse_args().stop:
        stop(mlog)
        if not TEST_CALL:
            sys.exit(0)

    # Check if the restart mode is enabled:
    if parser.parse_args().restart:
        mlog.info("Restarting Z-SOAR...")
        stop(mlog)
        startup(mlog, DEBUG)
        if not TEST_CALL:
            sys.exit(0)

    # Check if the status mode is enabled:
    if parser.parse_args().status:
        mlog.info("Checking the status of Z-SOAR...")
        import subprocess as subp

        daemon_pids = list(
            map(
                int,
                subp.check_output(["pgrep", "-f", "python3 zsoar_daemon.py"]).split(),
            )
        )
        if len(daemon_pids) > 0:
            mlog.info("Z-SOAR is running as a daemon. PID: ", daemon_pids)
        else:
            mlog.info("Z-SOAR is not running as a daemon.")

        # TODO: Further checks based on logs / statistics etc.

        if not TEST_CALL:
            sys.exit(0)

    mlog.info("No mode selected. Please use --help to see the available modes.")
    if not TEST_CALL:
        sys.exit(0)


if __name__ == "__main__":
    TEST_CALL = False
    main()
