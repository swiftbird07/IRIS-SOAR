# IRIS-SOAR
# Created by: Martin Offermann
# This module is the user interactive start point for the IRIS-SOAR project.
# It will load the prvided arguments and either start the setup mode or start/stop/restart the main isoar_worker.py or delegate this job to the daemon if enabled.

import subprocess
import sys
import os
import argparse
import psutil
import json

import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import isoar_daemon as isoar_daemon
import isoar_worker as isoar_worker

TEST_CALL = True  # Stays True if the script is called by the test script
case_ZOMBIE_PROCESSES = False  # If True, the script will case zombie processes when searching for the PID of a script. If you are using the developing, this should be set to False as tests from pytest will hang otherwise.
ALLOW_MULTIPLE_INSTANCES = (
    False  # If True, the script will allow multiple instances of IRIS-SOAR to run at the same time. This is not reccomended.
)


def add_arguments():
    """Parses the provided arguments.

    Args:
        args (list): The arguments

    Returns:
        parser (argparse.ArgumentParser): The parser
    """
    parser = argparse.ArgumentParser(description="IRIS-SOAR - Modular SOAR for Znuny/OTRS")
    parser.add_argument("--version", action="store_true", help="Print the version of IRIS-SOAR")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--setup", action="store_true", help="Install or Configure IRIS-SOAR")
    parser.add_argument("--start", action="store_true", help="Start IRIS-SOAR")
    parser.add_argument("--stop", action="store_true", help="Stop IRIS-SOAR")
    parser.add_argument("--restart", action="store_true", help="Restart IRIS-SOAR")
    parser.add_argument("--status", action="store_true", help="Show the status of IRIS-SOAR")
    parser.add_argument(
        "--allow-multiple-instances",
        action="store_true",
        help="Allow multiple instances of IRIS-SOAR to run at the same time. This is not reccomended.",
    )

    return parser


def get_script_pid(mlog, script):
    """Checks if the given script is running. Returns the PID if it is running.

    Args:
        mlog (logging_helper.Log): The logger
        script (str): The script name

    Returns:
        pid (int): The PID of the script (-1 if not running)
    """
    for q in psutil.process_iter():
        if q.name().lower().startswith("python"):
            try:
                if len(q.cmdline()) > 1 and script in q.cmdline()[1] and q.pid != os.getpid():
                    mlog.debug("'{}' script is running: {}. Command line: {}".format(script, str(q), str(q.cmdline())))
                    return q.pid
            except psutil.ZombieProcess:
                if q.pid != os.getpid() and case_ZOMBIE_PROCESSES:
                    mlog.warning(
                        "ZOMBIE Python process found: '{}' when searching for {} script. Will case it as instance of the searched script, as zombies can't be checked for command line.".format(
                            str(q), str(script)
                        )
                    )
                    return q.pid
                else:
                    mlog.warning(
                        "ZOMBIE Python process found: '{}' when searching for {} script. Will ignore it.".format(
                            str(q), str(script)
                        )
                    )
                    return -1

    mlog.debug("'{}' script is not running".format(script))
    return -1


def startup(mlog, DEBUG, ALLOW_MULTIPLE_INSTANCES):
    """Starts the main loop (called 'worker') or the daemon depending on the settings.

    Args:
        mlog (logging_helper.Log): The logger
        DEBUG (bool): If debug mode is enabled
        ALLOW_MULTIPLE_INSTANCES (bool): If multiple instances of IRIS-SOAR should be allowed

    Returns:
        None

    Raises:
        None
    """

    # Load the settings
    settings = config_helper.Config().cfg  #

    # Check if the daemon is enabled
    if settings["daemon"]["enabled"]:
        mlog.info("Starting the daemon...")
        # Check if daemon is already running
        if get_script_pid(mlog, "isoar_daemon.py") > 0:
            if not ALLOW_MULTIPLE_INSTANCES:
                mlog.critical(
                    "Daemon is already running. Use 'isoar.py --restart' to restart it or 'isoar.py --stop' to stop it manually."
                )
                raise SystemExit(1)
            else:
                mlog.warning("Daemon is already running. Multiple instances are allowed, so this is ignored. Continuing...")

        # Start the daemon with or without debug mode
        if DEBUG:
            popen = subprocess.Popen(
                [sys.executable, "isoar_daemon.py", "--debug_module"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        else:
            popen = subprocess.Popen(
                [sys.executable, "isoar_daemon.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

        if popen.returncode != None:
            mlog.critical("Could not start the daemon: System call failed. Subprocess returned: {}".format(popen.returncode))
            if not TEST_CALL:
                raise SystemExit(1)
        else:
            mlog.info("Daemon started")
    else:
        mlog.info("Daemon disabled. Starting the main loop (isoar_worker.py) directly...")
        # Check if worker is already running
        if get_script_pid(mlog, "isoar_worker.py") > 0:
            mlog.critical(
                "Worker is already running. Use 'isoar.py --restart' to restart it or 'isoar.py --stop' to stop it manually."
            )
            raise SystemExit(1)

        if get_script_pid(mlog, "isoar_daemon.py") > 0:
            mlog.critical("Daemon is still running. Use 'isoar.py --stop' to stop it manually.")
            raise SystemExit(1)

        # Start the worker manually
        return_code = isoar_worker.main(settings, debug=DEBUG)

        if return_code != None:
            mlog.critical("Could not start the worker: System call failed. Subprocess returned: {}".format(popen.returncode))
            if not TEST_CALL:
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
    mlog.info("Stopping IRIS-SOAR...")
    did_something = False

    # Check if daemons are running
    while (daemon_pid := get_script_pid(mlog, "isoar_daemon.py")) > 0:
        # Kill the daemon
        mlog.info(f"Found running daemon (pid={daemon_pid}). Killing it...")
        if os.system(f"kill -9 {daemon_pid}"):
            mlog.critical("Could not stop the daemon: System call failed.")
            if not TEST_CALL:
                raise SystemExit(1)
        else:
            mlog.info("Daemon script stopped")
            did_something = True

    if not did_something:
        mlog.info("Daemon not running")

    # Check if worker is running
    worker_pid = get_script_pid(mlog, "isoar_worker.py")
    if worker_pid > 0:
        # Kill the worker
        mlog.info("Stopping the worker...")
        if os.system(f"kill -9 {worker_pid}"):
            mlog.critical("Could not stop the worker: System call failed.")
            if not TEST_CALL:
                raise SystemExit(1)
        else:
            mlog.info("Worker script stopped")
            did_something = True
    else:
        mlog.info("Worker script not running")

    if not did_something:
        mlog.warning("Nothing to stop!")
    else:
        mlog.info("IRIS-SOAR stopped")


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
        print("Welcome to the IRIS-SOAR setup!")
        print("This setup will guide you through the installation and configuration of IRIS-SOAR.")
        print("Please note that this setup is not yet finished and will be extended in the future.")
        print("If you want to skip the setup, you can edit the config file manually.")
        print("The config file is located at: " + os.path.join(os.getcwd(), "config", "isoar.cfg.yml"))
        print(
            "\nYou can also continue the setup by running the setup mode again. To start from the beginning, delete the config file."
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
            "Please enter the minimum interval between IRIS-SOAR worker processes in minutes used by the daemon (0 to immediatly start the next worker process if the last one exited):"
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
        if type(size) == int and size >= 0:
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
        # Ask if log files should be split for each module
        print("")
        print("Do you want to split the log files for each module?")
        response = setup_ask("n", available_responses_list=["y", "n"])
        if response == "y":
            settings["logging"]["log_file_split_module"] = True
        elif response == "n":
            settings["logging"]["log_file_split_module"] = False
        settings["setup"]["setup_step"] = 11
        config_helper.save_config(settings)
        if not continue_steps:
            return
        setup(11)

    elif settings["setup"]["setup_step"] == 11 or step == 11:
        print("")
        print("Setup finished. You can now start the daemon with the command 'isoar.py --start'.")
        settings["setup"]["setup_step"] = 0
        config_helper.save_config(settings)
        if not TEST_CALL and not continue_steps:
            sys.exit(0)

    # TODO: Add Znuny/OTRS connection setup
    # TODO: Add integration setup

    print("Setup stopped. Please run the setup again to continue.")


#
# znuny_otrs:
#    hostname:
#    web_service_name:
#    api_customer_user:
#    api_customer_password:

# ...


def main():
    """The main function of the isoar.py script.

    Args:
        None

    Returns:
        None
    """

    parser = add_arguments()
    args = parser.parse_args()

    # Create the module's logger
    mlog = logging_helper.Log("isoar")

    # Check if at least one argument is provided:
    if type(args) != argparse.Namespace or len(sys.argv) == 1:
        print("No mode selected. Please use --help to see the available modes.")
        if not TEST_CALL:
            sys.exit(0)

    # Check if the version mode is enabled:
    if parser.parse_args().version:
        import pkg_resources

        version = pkg_resources.get_distribution("ISOARpkg").version
        print("IRIS-SOAR version: " + version)
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

    if parser.parse_args().allow_multiple_instances:
        mlog.warning(
            "You have enabled the option to allow multiple instances of IRIS-SOAR to run at the same time. This is not reccomended."
        )
        ALLOW_MULTIPLE_INSTANCES = True
    else:
        ALLOW_MULTIPLE_INSTANCES = False

    # Check if the start mode is enabled:
    if parser.parse_args().start:
        mlog.info("Starting IRIS-SOAR")
        startup(mlog, DEBUG, ALLOW_MULTIPLE_INSTANCES)
        if not TEST_CALL:
            sys.exit(0)

    # Check if the stop mode is enabled:
    if parser.parse_args().stop:
        stop(mlog)
        if not TEST_CALL:
            sys.exit(0)

    # Check if the restart mode is enabled:
    if parser.parse_args().restart:
        mlog.info("Restarting IRIS-SOAR...")
        stop(mlog)
        startup(mlog, DEBUG, ALLOW_MULTIPLE_INSTANCES)
        if not TEST_CALL:
            sys.exit(0)

    # Check if the status mode is enabled:
    if parser.parse_args().status:
        mlog.info("Checking the status of IRIS-SOAR...")

        # Check if daemons are running
        daemon_pid = get_script_pid(mlog, "isoar_daemon.py")
        if daemon_pid > 0:
            # Print the daemon
            mlog.info(f"Found running daemon (pid={daemon_pid}).")

            mlog.info("")
            mlog.info("\tDaemon information:")
            mlog.info("\t" + str(psutil.Process(daemon_pid)))

            if DEBUG:
                mlog.info(
                    "\n\tDebug mode. Printing extended process info:\n"
                    + json.dumps(psutil.Process(daemon_pid).as_dict(), indent=2)
                )

            mlog.info("")
        else:
            mlog.info("No running daemon found.")

        # Check if worker is running
        worker_pid = get_script_pid(mlog, "isoar_worker.py")
        if worker_pid > 0:
            mlog.info(f"Found running worker (pid={worker_pid}).")
            mlog.info("")
            mlog.info("\tWorker information:")
            mlog.info("\t" + psutil.Process(worker_pid))
            if DEBUG:
                mlog.info(
                    "\n\tDebug mode. Printing extended process info:\n"
                    + json.dumps(psutil.Process(daemon_pid).as_dict(), indent=2)
                )
        else:
            mlog.info("No running worker found.")

        if daemon_pid == 0 and worker_pid == 0:
            mlog.info("IRIS-SOAR is not running.")

        if not TEST_CALL:
            sys.exit(0)

    mlog.info("No mode selected. Please use --help to see the available modes.")
    if not TEST_CALL:
        sys.exit(0)


if __name__ == "__main__":
    TEST_CALL = False
    main()
