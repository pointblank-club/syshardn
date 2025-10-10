"""
OS Detection Module

Detects the operating system, version, and distribution.
"""

import platform
import sys
from typing import Dict, Any, Optional
from pathlib import Path


class OSDetector:
    """Detects operating system details."""

    def __init__(self):
        """Initialize OS detector."""
        self.os_info = self._detect_os()

    def _detect_os(self) -> Dict[str, Any]:
        """
        Detect operating system and version.

        Returns:
            Dictionary with OS information
        """
        system = platform.system().lower()

        if system == "windows":
            return self._detect_windows()
        elif system == "linux":
            return self._detect_linux()
        elif system == "darwin":
            return self._detect_macos()
        else:
            return {
                "os": "unknown",
                "version": platform.release(),
                "architecture": platform.machine(),
            }

    def _detect_windows(self) -> Dict[str, Any]:
        """Detect Windows version."""
        version = platform.release()
        build = platform.version()

        edition = "Unknown"
        if version == "10":
            build_number = int(build.split(".")[-1]) if "." in build else 0
            if build_number >= 22000:
                edition = "11"
            else:
                edition = "10"
        else:
            edition = version

        return {
            "os": "windows",
            "version": edition,
            "build": build,
            "architecture": platform.machine(),
            "platform": platform.platform(),
        }

    def _detect_linux(self) -> Dict[str, Any]:
        """Detect Linux distribution and version."""
        info = {
            "os": "linux",
            "distro": "unknown",
            "version": "unknown",
            "architecture": platform.machine(),
            "kernel": platform.release(),
        }

        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                with open(os_release, "r") as f:
                    release_info = {}
                    for line in f:
                        line = line.strip()
                        if "=" in line:
                            key, value = line.split("=", 1)
                            release_info[key] = value.strip('"')

                    info["distro"] = release_info.get("ID", "unknown").lower()
                    info["version"] = release_info.get("VERSION_ID", "unknown")
                    info["distro_name"] = release_info.get("NAME", "Unknown")

            except Exception:
                pass

        if info["distro"] == "unknown":
            if Path("/etc/debian_version").exists():
                info["distro"] = "debian"
                try:
                    with open("/etc/debian_version", "r") as f:
                        info["version"] = f.read().strip()
                except Exception:
                    pass

            elif Path("/etc/redhat-release").exists():
                try:
                    with open("/etc/redhat-release", "r") as f:
                        release = f.read().strip().lower()
                        if "centos" in release:
                            info["distro"] = "centos"
                        elif "red hat" in release or "rhel" in release:
                            info["distro"] = "rhel"
                        elif "fedora" in release:
                            info["distro"] = "fedora"
                except Exception:
                    pass

        return info

    def _detect_macos(self) -> Dict[str, Any]:
        """Detect macOS version."""
        return {
            "os": "macos",
            "version": platform.mac_ver()[0],
            "architecture": platform.machine(),
            "platform": platform.platform(),
        }

    def get_os_type(self) -> str:
        """
        Get the OS type.

        Returns:
            'windows', 'linux', 'macos', or 'unknown'
        """
        return self.os_info.get("os", "unknown")

    def get_version(self) -> str:
        """
        Get the OS version.

        Returns:
            OS version string
        """
        return self.os_info.get("version", "unknown")

    def get_distro(self) -> Optional[str]:
        """
        Get Linux distribution (Linux only).

        Returns:
            Distribution name or None
        """
        if self.get_os_type() == "linux":
            return self.os_info.get("distro")
        return None

    def is_supported(self, rule_metadata: Dict[str, Any]) -> bool:
        """
        Check if current OS is supported by a rule.

        Args:
            rule_metadata: Rule metadata section

        Returns:
            True if OS is supported
        """
        rule_os = rule_metadata.get("os", "").lower()

        if rule_os != self.get_os_type():
            return False

        if rule_os == "linux":
            distro = self.get_distro()
            supported_distros = rule_metadata.get("distros", [])

            if distro and supported_distros:
                if distro not in supported_distros:
                    return False

                versions = rule_metadata.get("versions", {})
                if distro in versions:
                    supported_versions = versions[distro]
                    current_version = self.get_version()
                    if current_version not in supported_versions:
                        return False

        elif rule_os == "windows":
            supported_versions = rule_metadata.get("versions", [])
            current_version = self.get_version()

            if supported_versions and current_version not in supported_versions:
                return False

        return True

    def get_info(self) -> Dict[str, Any]:
        """
        Get complete OS information.

        Returns:
            Dictionary with all OS details
        """
        return self.os_info.copy()

    def is_admin(self) -> bool:
        """
        Check if running with administrator/root privileges.

        Returns:
            True if running as admin/root
        """
        if self.get_os_type() == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            import os
            return os.geteuid() == 0
