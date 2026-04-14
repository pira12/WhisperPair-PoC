"""
ADB Manager - Android Debug Bridge wrapper for WhisperPair
Detects connected Android phones and triggers Bluetooth pairing via ADB.

For Find My Device registration, the phone must pair through Google Play
Services' Fast Pair flow (not regular Bluetooth pairing). This module
enables Bluetooth and verifies new bonds after the user accepts the
Fast Pair notification on their phone.
"""

import subprocess
import re


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

    def get_bonded_addresses(self, device_id):
        """Parse bonded device addresses from dumpsys bluetooth_manager."""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "dumpsys", "bluetooth_manager"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return set()

            addresses = set()
            in_bonded = False
            for line in result.stdout.splitlines():
                if "Bonded devices:" in line:
                    in_bonded = True
                    continue
                if in_bonded:
                    stripped = line.strip()
                    if not stripped:
                        break
                    match = re.match(r"([0-9A-Fa-f:]{17})", stripped)
                    if match:
                        addresses.add(match.group(1).upper())
                    else:
                        break
            return addresses
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return set()

    def verify_new_bond(self, device_id, bonded_before):
        """Check if any new device was bonded compared to a baseline snapshot."""
        bonded_after = self.get_bonded_addresses(device_id)
        new_devices = bonded_after - bonded_before
        return len(new_devices) > 0
