"""
ADB Manager - Android Debug Bridge wrapper for WhisperPair
Detects connected Android phones and triggers Bluetooth pairing via ADB.

For Find My Device registration, the phone must pair through Google Play
Services' Fast Pair flow (not regular Bluetooth pairing). This module
enables Bluetooth and verifies new bonds after the user accepts the
Fast Pair notification on their phone.
"""

import os
import subprocess
import re


def _find_user_home():
    """Find the real (non-root) user's home directory."""
    import pwd

    # 1. SUDO_USER is set when using sudo
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass

    # 2. Look for the first /home/* user that has .android/adbkey
    home_base = "/home"
    if os.path.isdir(home_base):
        for entry in os.listdir(home_base):
            candidate = os.path.join(home_base, entry, ".android", "adbkey")
            if os.path.isfile(candidate):
                return os.path.join(home_base, entry)

    # 3. Fall back to the invoking user's uid (covers non-sudo root)
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        return os.environ.get("HOME", "/root")


def _adb_env():
    """Build environment so ADB works when the backend runs as root via sudo.

    The ADB server is typically started by the normal user and owns the
    USB authorization keys.  When we run under sudo, ADB defaults to
    root's home and either starts a second (unauthorised) server or fails
    to talk to the existing one.  Fix: find the real user's home, point
    ADB_VENDOR_KEYS at their keys, and set HOME so ADB connects to the
    existing server.
    """
    env = os.environ.copy()
    if os.getuid() == 0:
        user_home = _find_user_home()

        adb_keys = os.path.join(user_home, ".android", "adbkey")
        if os.path.isfile(adb_keys):
            env["ADB_VENDOR_KEYS"] = adb_keys
        env["HOME"] = user_home

        android_home = os.path.join(user_home, "Android", "Sdk")
        env.setdefault("ANDROID_HOME", android_home)

        # Ensure adb binary is on PATH (root's PATH often lacks user SDK dirs)
        platform_tools = os.path.join(android_home, "platform-tools")
        if os.path.isdir(platform_tools):
            path = env.get("PATH", "/usr/bin:/bin")
            if platform_tools not in path:
                env["PATH"] = platform_tools + ":" + path

        # Tell ADB to connect to the user's existing server (port 5037)
        # instead of starting a new root-owned server.
        env.setdefault("ANDROID_ADB_SERVER_PORT", "5037")
    return env


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
                env=_adb_env(),
            )
        except Exception:
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
        env = _adb_env()
        info = {"id": device_id, "model": "", "android_version": "", "bt_enabled": False}
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.product.model"],
                capture_output=True, text=True, timeout=5, env=env,
            )
            if result.returncode == 0:
                info["model"] = result.stdout.strip()

            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=5, env=env,
            )
            if result.returncode == 0:
                info["android_version"] = result.stdout.strip()

            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "settings", "get", "global", "bluetooth_on"],
                capture_output=True, text=True, timeout=5, env=env,
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
                capture_output=True, text=True, timeout=10, env=_adb_env(),
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def get_bonded_addresses(self, device_id):
        """Parse bonded device addresses from dumpsys bluetooth_manager."""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "dumpsys", "bluetooth_manager"],
                capture_output=True, text=True, timeout=10, env=_adb_env(),
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

