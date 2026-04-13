"""
ADB Manager - Android Debug Bridge wrapper for WhisperPair
Detects connected Android phones and triggers Bluetooth pairing via ADB.
"""

import subprocess


class ADBManager:
    """Wraps ADB shell commands for Android phone interaction."""

    def list_devices(self):
        """List connected ADB devices with model info."""
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0:
            return []

        devices = []
        for line in result.stdout.strip().splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            device_id = parts[0]
            status = parts[1]
            model = ""
            for part in parts[2:]:
                if part.startswith("model:"):
                    model = part.split(":", 1)[1]
                    break
            devices.append({
                "id": device_id,
                "status": status,
                "model": model,
            })
        return devices

    def get_device_info(self, device_id):
        """Get detailed info about a connected Android device."""
        info = {"id": device_id, "model": "", "android_version": "", "bt_enabled": False}
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.product.model"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                info["model"] = result.stdout.strip()

            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                info["android_version"] = result.stdout.strip()

            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "settings", "get", "global", "bluetooth_on"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                info["bt_enabled"] = result.stdout.strip() == "1"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return info

    def enable_bluetooth(self, device_id):
        """Enable Bluetooth on the Android device."""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "cmd", "bluetooth_manager", "enable"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def pair_device(self, device_id, br_edr_address):
        """Pair Android phone with target device. Tries multiple approaches for Android 14."""
        # Approach 1: bluetooth_manager pair command
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "cmd", "bluetooth_manager", "pair", br_edr_address],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and "error" not in result.stdout.lower():
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Approach 2: Bluetooth pairing intent
        try:
            result = subprocess.run(
                [
                    "adb", "-s", device_id, "shell", "am", "start",
                    "-a", "android.bluetooth.device.action.PAIRING_REQUEST",
                    "-e", "android.bluetooth.device.extra.DEVICE", br_edr_address,
                ],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return False

    def verify_paired(self, device_id, br_edr_address):
        """Check if the target device appears in the phone's bonded devices."""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "cmd", "bluetooth_manager", "list-bonded-devices"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return br_edr_address.upper() in result.stdout.upper()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False
