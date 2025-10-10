"""
Executor Factory

Creates the appropriate executor based on the operating system.
"""

from syshardn.executors.base_executor import BaseExecutor
from syshardn.executors.windows_executor import WindowsExecutor
from syshardn.executors.linux_executor import LinuxExecutor


class ExecutorFactory:
    """Factory for creating platform-specific executors."""
    
    @staticmethod
    def create_executor(os_type: str) -> BaseExecutor:
        """
        Create an executor for the specified operating system.
        
        Args:
            os_type: Operating system type ('windows', 'linux', 'macos')
        
        Returns:
            Platform-specific executor instance
        
        Raises:
            ValueError: If os_type is not supported
        """
        os_type = os_type.lower()
        
        if os_type == "windows":
            return WindowsExecutor()
        elif os_type == "linux":
            return LinuxExecutor()
        elif os_type in ("macos", "darwin"):
            # macOS/darwin uses Linux executor (Unix-based)
            return LinuxExecutor()
        else:
            raise ValueError(f"Unsupported operating system: {os_type}")
