# Z-SOAR
# Created by: Martin Offermann
# This module is the user interactive start point for the Z-SOAR project.
# It will load the prvided arguments and either start the setup mode or start/stop/restart the main zsoar_worker.py or delegate this job to the daemon if enabled.

import sys
import os
import argparse

import lib.load_config as load_config
import lib.logging_helper as logging_helper

TEST_CALL = True  # Stays True if the script is called by the test script


def parse_arguments():
    """Parses the provided arguments.

    Args:
        args (list): The arguments

    Returns:
        parser (argparse.ArgumentParser): The parser
    """
    parser = argparse.ArgumentParser(description="Z-SOAR - Modular SOAR for Znuny/OTRS")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "--setup", action="store_true", help="Install or Configure Z-SOAR"
    )
    parser.add_argument("--start", action="store_true", help="Start Z-SOAR")
    parser.add_argument("--stop", action="store_true", help="Stop Z-SOAR")
    parser.add_argument("--restart", action="store_true", help="Restart Z-SOAR")
    parser.add_argument(
        "--status", action="store_true", help="Show the status of Z-SOAR"
    )

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
    if load_config.check_config():
        settings = load_config.load_config()  #
    else:
        mlog.critical(
            "The config file is not valid. Please check the config file and try again."
        )
        if not TEST_CALL:
            sys.exit(1)

    # Check if the daemon is enabled
    if settings["daemon"]["enabled"]:
        # Start the daemon
        mlog.info("Starting the daemon")
        os.system("python3 lib/daemon.py")
    else:
        # Start the main loop
        mlog.info("Daemon disabled. Starting the main loop directly.")
        os.system("python3 zsoar_worker.py")


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


def main():
    """The main function of the zsoar.py script.

    Args:
        None

    Returns:
        None
    """

    parser = parse_arguments()

    # Create the logger
    mlog = logging_helper.Log.get_logger("zsoar_start")

    # Check if the version mode is enabled:
    if parser.parse_args().version:
        mlog.info("Z-SOAR Version 0.0.1 (alpha)")
        if not TEST_CALL:
            sys.exit(0)

    # Check if debug mode is enabled:
    if parser.parse_args().debug:
        os.environ["DEBUG"] = "True"
        DEBUG = True
        mlog.info("* Debug mode is enabled *")
        mlog.setLevel("debug")
    else:
        DEBUG = False

    # Check if the setup mode is enabled:
    if parser.parse_args().setup:
        mlog.info("Starting the setup...")
        os.system("python3 lib/setup.py")
        if not TEST_CALL:
            sys.exit(0)

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

        # TODO Further checks based on logs / statistics etc.

        if not TEST_CALL:
            sys.exit(0)

    mlog.info("No mode selected. Please use --help to see the available modes.")
    if not TEST_CALL:
        sys.exit(0)


if __name__ == "__main__":
    TEST_CALL = False
    main()
