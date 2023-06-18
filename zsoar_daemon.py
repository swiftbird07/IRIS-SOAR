# Z-SOAR
# Created by: Martin Offermann
# This module is the daemon for the Z-SOAR project. It is used to start the main zsoar_worker.py script on a regular interval.
# The interval is defined in the config file.

import time
import lib.config_helper as config_helper
import lib.logging_helper as logging_helper
import zsoar_worker as zsoar_worker
from argparse import ArgumentParser

TEST_CALL = True  # Stays True if the script is called by the test script


def main(TEST_CALL):
    """Main function of the daemon.

    Args:
        None

    Returns:
        None
    """
    # Get the logger
    mlog = logging_helper.Log("zsoar_daemon")

    if TEST_CALL or args.debug_module:
        mlog.set_level("DEBUG")
        mlog.debug("Debug mode enabled.")

    # Get the config
    try:
        configObj = config_helper.Config()
        cfg = configObj.cfg
    except TypeError as e:
        mlog.critical("Could not load config. Check the config_helper logs. Error: " + str(e))
        if not TEST_CALL:
            exit(1)

    if cfg["daemon"]["enabled"] == False:
        mlog.critical("The daemon is disabled in the config. Exiting.")
        if not TEST_CALL:
            exit(1)

    # Get the interval
    interval = cfg["daemon"]["interval_min"]

    # Start the main loop
    while True:
        mlog.info("Starting zsoar_worker.py")
        try:
            zsoar_worker.main(cfg, fromDaemon=True, debug=args.debug_module)
            mlog.info("zsoar_worker.py finished. Waiting for next run.")
        except Exception as e:
            mlog.error(
                "zsoar_worker.py failed. See the zsoar_worker logs for more information. Error: " + str(e),
            )

        # Reload config in case it was changed
        try:
            cfg_old = cfg
            configObj = config_helper.Config()
            cfg = configObj.cfg

            if cfg != cfg_old:
                mlog.info("Config reloaded.")
        except TypeError as e:
            mlog.warning(
                "Could not reload new config. Check the config_helper logs. Will use old working config. Error: " + str(e)
            )

        if TEST_CALL:
            break

        time.sleep(interval * 60)


if __name__ == "__main__":
    # Parse if debug argument was given
    parser_daemon = ArgumentParser()
    parser_daemon.add_argument(
        "--debug_module",
        action="store_true",
    )
    args = parser_daemon.parse_args()

    main(TEST_CALL == False)
