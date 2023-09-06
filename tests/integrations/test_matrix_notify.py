# IRIS-SOAR
# Created by: Martin Offermann
# This test module is used to test the matrix_notify integration.
from integrations.matrix_notify import irsoar_notify
from lib.config_helper import Config

TEST_ROOM_ID = "!qyLpnAmwoEvfFzbSgt:matrix.fulminata.eu"


def test_irsoar_notify():
    # Test the notify function
    config = Config().cfg
    config = config["integrations"]["matrix_notify"]
    config["matrix_room_id"] = TEST_ROOM_ID

    assert irsoar_notify(config, "A Test Message", True) == True, "irsoar_notify() should return True"
    assert (
        irsoar_notify(config, "A Test Message", False) == False
    ), "irsoar_notify() should return False if multiple same messages are sent"
