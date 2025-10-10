"""
Base Executor

Abstract base class for platform-specific executors.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from pathlib import Path
from datetime import datetime
import json


class BaseExecutor(ABC):
    """Base class for all executors."""
    
    def __init__(self):
        """Initialize base executor."""
        self.logger = None
        try:
            from syshardn.utils.logger import get_logger
            self.logger = get_logger(self.__class__.__name__)
        except ImportError:
            pass
    
    @abstractmethod
    def check_rule(self, rule: Dict[str, Any], hardening_level: str) -> Dict[str, Any]:
        """
        Check if a rule is compliant.
        
        Args:
            rule: Rule dictionary
            hardening_level: Hardening level to check
        
        Returns:
            Result dictionary with status, message, etc.
        """
        pass
    
    @abstractmethod
    def apply_rule(self, rule: Dict[str, Any], hardening_level: str, backup_dir: str) -> Dict[str, Any]:
        """
        Apply a hardening rule.
        
        Args:
            rule: Rule dictionary
            hardening_level: Hardening level to apply
            backup_dir: Directory for backups
        
        Returns:
            Result dictionary with status, message, etc.
        """
        pass
    
    @abstractmethod
    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a system command.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
        
        Returns:
            Dictionary with returncode, stdout, stderr
        """
        pass
    
    def get_hardening_value(self, rule: Dict[str, Any], level: str) -> Any:
        """
        Get the hardening value for a specific level.
        
        Args:
            rule: Rule dictionary
            level: Hardening level
        
        Returns:
            Hardening value
        """
        levels = rule.get("rule", {}).get("hardening_levels", {})
        level_config = levels.get(level, {})
        
        if not level_config.get("enabled", False):
            return None
        
        return level_config.get("value")
    
    def substitute_variables(self, command: str, variables: Dict[str, Any]) -> str:
        """
        Substitute variables in command strings.
        
        Args:
            command: Command with {{variable}} placeholders
            variables: Dictionary of variable values
        
        Returns:
            Command with substituted values
        """
        result = command
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))
        return result
    
    def create_backup(self, rule: Dict[str, Any], backup_dir: str) -> str:
        """
        Create a backup before applying a rule.
        
        Args:
            rule: Rule dictionary
            backup_dir: Backup directory
        
        Returns:
            Path to backup file
        """
        rule_id = rule.get("rule", {}).get("id", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        backup_path = Path(backup_dir) / f"{rule_id}_{timestamp}.backup"
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        rollback = rule.get("rollback", {})
        backup_command = rollback.get("backup_command")
        
        if backup_command:
            variables = {
                "backup_location": str(backup_path),
                "backup_dir": backup_dir,
                "timestamp": timestamp,
            }
            
            cmd = self.substitute_variables(backup_command, variables)
            result = self.execute_command(cmd)
            
            if result["returncode"] != 0:
                if self.logger:
                    self.logger.warning(f"Backup command failed for {rule_id}")

        metadata_path = backup_path.with_suffix(".json")
        with open(metadata_path, "w") as f:
            json.dump({
                "rule_id": rule_id,
                "timestamp": timestamp,
                "rule": rule,
            }, f, indent=2)
        
        return str(backup_path)
    
    def verify_check(self, rule: Dict[str, Any], hardening_level: str) -> bool:
        """
        Verify that a rule is compliant after remediation.
        
        Args:
            rule: Rule dictionary
            hardening_level: Hardening level
        
        Returns:
            True if compliant, False otherwise
        """
        result = self.check_rule(rule, hardening_level)
        return result.get("status") == "pass"
    
    def rollback_from_backup(self, backup_file: str) -> None:
        """
        Rollback changes from a backup file.
        
        Args:
            backup_file: Path to backup file (should have .backup extension)
        """
        backup_path = Path(backup_file)
        metadata_path = backup_path.with_suffix(".json")
        
        if not backup_path.exists():
            raise ValueError(f"Backup file not found: {backup_path}")
        
        if not metadata_path.exists():
            raise ValueError(f"Backup metadata not found: {metadata_path}")

        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        rule = metadata.get("rule", {})
        rollback = rule.get("rollback", {})
        restore_command = rollback.get("restore_command")
        
        if not restore_command:
            raise ValueError("No restore command found in rule")

        variables = {
            "backup_location": str(backup_path),
            "backup_dir": str(backup_path.parent),
        }
        
        cmd = self.substitute_variables(restore_command, variables)
        if self.logger:
            self.logger.info(f"Executing restore command: {cmd[:200]}...")
        result = self.execute_command(cmd)
        
        if result["returncode"] != 0:
            error_msg = result.get("stderr", "").strip() or result.get("stdout", "").strip() or "Unknown error"
            if self.logger:
                self.logger.error(f"Restore command failed with code {result['returncode']}: {error_msg}")
            raise RuntimeError(f"Restore command failed (exit code {result['returncode']}): {error_msg}")
