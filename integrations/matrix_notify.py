# Integration for Z-SOAR
# Created by: Martin Offermann
# This module is used to integrate Z-SOAR with Matrix for notifications.
#
# This module is capable of:
# [X] Notifications
# [ ] User interactive setup.
#
# Integration Version: 0.0.1
from lib.generic_helper import get_from_cache, add_to_cache, dict_get
from lib.logging_helper import Log
import matrix_client.api as matrix_client_api
import traceback


def zs_notify(config: dict, message: str, allow_multiple: bool = False) -> bool:
    """
    This function is used to send notifications to Matrix.
    :param case_file: The detection case object.
    :param config: The configuration object.
    :param message: The message to send.
    :param allow_multiple: If multiple notifications with the same message should be allowed (default: False)

    :return: True if the notification was sent successfully, False otherwise.
    """
    mlog = Log(
        "matrix_notify",
        log_level_file=config["logging"]["log_level_file"],
        log_level_stdout=config["logging"]["log_level_stdout"],
    )

    mlog.info("zs_notify called with message to send: '" + message + "'")

    # First check if a similar notification was already sent by looking at the cache of sent notifications
    mlog.debug("Checking if notification was already sent...")

    notifications = get_from_cache("matrix_notify", "notifications", "LIST")
    if notifications is None:
        notifications = []

    if not allow_multiple and message in notifications:
        mlog.info("Notification was already sent. Skipping sending of message: " + message)
        return False

    mlog.debug("Notification was not sent before.")

    # Send the alert to Matrix
    MATRIX_SERVER = config["matrix_server"]
    MATRIX_ACCESS_TOKEN = config["matrix_access_token"]
    MATRIX_ROOM_ID = config["matrix_room_id"]

    mlog.debug("Sending notification to Matrix...")
    matrix_client = matrix_client_api.MatrixHttpApi(MATRIX_SERVER, token=MATRIX_ACCESS_TOKEN)
    try:
        response = matrix_client.send_message_event(
            room_id=MATRIX_ROOM_ID,
            event_type="m.room.message",
            content={"msgtype": "m.text", "format": "org.matrix.custom.html", "body": message, "formatted_body": message},
        )

        if dict_get(response, "event_id") is None:
            mlog.error("Failed to send notification to Matrix: " + response.text)
            return False

    except Exception as e:
        mlog.error("Failed to send notification to Matrix: " + traceback.format_exc())
        return False

    mlog.info("Successfully sent notification to Matrix.")

    # Add the notification to the list of sent notifications
    mlog.debug("Adding notification to cache...")
    add_to_cache("matrix_notify", "notifications", "LIST", message)

    return True
