# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the matrix_notify integration.
from integrations.matrix_notify import zs_notify
from lib.config_helper import Config

TEST_ROOM_ID = "!qyLpnAmwoEvfFzbSgt:matrix.fulminata.eu"


def test_zs_notify():
    # Test the notify function
    config = Config().cfg
    config = config["integrations"]["matrix_notify"]
    config["matrix_room_id"] = TEST_ROOM_ID

    assert zs_notify(config, "A Test Message", True) == True, "zs_notify() should return True"
    assert (
        zs_notify(config, "A Test Message", False) == False
    ), "zs_notify() should return False if multiple same messages are sent"
