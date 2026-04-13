import unittest
from unittest.mock import patch, MagicMock

from adb_manager import ADBManager


class TestADBManagerListDevices(unittest.TestCase):

    @patch("adb_manager.subprocess.run")
    def test_list_devices_returns_connected_phones(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\nR5CT720B9HF device usb:1-2 product:starqltesq model:SM_G965U device:starqltesq transport_id:3\n\n",
        )
        mgr = ADBManager()
        devices = mgr.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["id"], "R5CT720B9HF")
        self.assertEqual(devices[0]["model"], "SM_G965U")
        self.assertEqual(devices[0]["status"], "device")

    @patch("adb_manager.subprocess.run")
    def test_list_devices_empty_when_none_connected(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\n\n",
        )
        mgr = ADBManager()
        devices = mgr.list_devices()
        self.assertEqual(devices, [])

    @patch("adb_manager.subprocess.run")
    def test_list_devices_handles_adb_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("adb not found")
        mgr = ADBManager()
        devices = mgr.list_devices()
        self.assertEqual(devices, [])


class TestADBManagerBluetooth(unittest.TestCase):

    @patch("adb_manager.subprocess.run")
    def test_enable_bluetooth_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        mgr = ADBManager()
        result = mgr.enable_bluetooth("R5CT720B9HF")
        self.assertTrue(result)
        mock_run.assert_called_once_with(
            ["adb", "-s", "R5CT720B9HF", "shell", "cmd", "bluetooth_manager", "enable"],
            capture_output=True,
            text=True,
            timeout=10,
        )

    @patch("adb_manager.subprocess.run")
    def test_pair_device_tries_bluetooth_manager_first(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        mgr = ADBManager()
        result = mgr.pair_device("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(result)

    @patch("adb_manager.subprocess.run")
    def test_pair_device_falls_back_to_intent(self, mock_run):
        # First call (bluetooth_manager pair) fails, second call (am start intent) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="Error"),
            MagicMock(returncode=0, stdout="Starting: Intent"),
        ]
        mgr = ADBManager()
        result = mgr.pair_device("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2)

    @patch("adb_manager.subprocess.run")
    def test_verify_paired_finds_device(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Bonded devices:\nAA:BB:CC:DD:EE:FF\n01:02:03:04:05:06\n",
        )
        mgr = ADBManager()
        result = mgr.verify_paired("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(result)

    @patch("adb_manager.subprocess.run")
    def test_verify_paired_device_not_found(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Bonded devices:\n01:02:03:04:05:06\n",
        )
        mgr = ADBManager()
        result = mgr.verify_paired("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
