"""
Windows Executor

Executes checks and remediations on Windows systems.
"""

import subprocess
from typing import Dict, Any
from syshardn.executors.base_executor import BaseExecutor


class WindowsExecutor(BaseExecutor):
    """Executor for Windows systems."""
    
    def __init__(self):
        """Initialize Windows executor."""
        super().__init__()
    
    def check_rule(self, rule: Dict[str, Any], hardening_level: str) -> Dict[str, Any]:
        """
        Check if a Windows rule is compliant.
        
        Args:
            rule: Rule dictionary
            hardening_level: Hardening level
        
        Returns:
            Result dictionary
        """
        rule_id = rule.get("rule", {}).get("id")
        description = rule.get("rule", {}).get("description", "")
        
        try:
            check = rule.get("check", {})
            command = check.get("command", "")
            expected = check.get("expected", {})
            timeout = check.get("timeout", 30)

            hardening_value = self.get_hardening_value(rule, hardening_level)
            if hardening_value is None:
                return {
                    "rule_id": rule_id,
                    "status": "skipped",
                    "message": f"Rule not enabled for {hardening_level} level",
                }

            variables = {
                "hardening_value": hardening_value,
                "hardening_level": hardening_level,
            }
            cmd = self.substitute_variables(command, variables)
            
            result = self.execute_command(cmd, timeout)
            
            if result["returncode"] != 0:
                return {
                    "rule_id": rule_id,
                    "status": "fail",
                    "message": f"Check command failed: {result['stderr']}",
                    "current_value": None,
                }

            current_value = result["stdout"].strip()

            expected_value_template = expected.get("value")
            if expected_value_template is None:
                expected_value = hardening_value
            elif isinstance(expected_value_template, str):
                expected_value = self.substitute_variables(expected_value_template, variables)
            else:
                expected_value = expected_value_template

            is_compliant = self._compare_values(
                current_value,
                expected_value,
                expected.get("operator", "=="),
                expected.get("type", "string"),
            )
            
            if is_compliant:
                return {
                    "rule_id": rule_id,
                    "status": "pass",
                    "message": f"Compliant ({current_value})",
                    "current_value": current_value,
                }
            else:
                return {
                    "rule_id": rule_id,
                    "status": "fail",
                    "message": f"Non-compliant (current: {current_value}, expected: {expected_value})",
                    "current_value": current_value,
                    "expected_value": expected_value,
                }
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking rule {rule_id}: {e}")
            return {
                "rule_id": rule_id,
                "status": "error",
                "message": str(e),
            }
    
    def apply_rule(self, rule: Dict[str, Any], hardening_level: str, backup_dir: str) -> Dict[str, Any]:
        """
        Apply a Windows hardening rule.
        
        Args:
            rule: Rule dictionary
            hardening_level: Hardening level
            backup_dir: Backup directory
        
        Returns:
            Result dictionary
        """
        rule_id = rule.get("rule", {}).get("id")
        
        try:
            hardening_value = self.get_hardening_value(rule, hardening_level)
            if hardening_value is None:
                return {
                    "rule_id": rule_id,
                    "status": "skipped",
                    "message": f"Rule not enabled for {hardening_level} level",
                }

            remediation = rule.get("remediation", {})
            prerequisites = remediation.get("prerequisites", [])
            
            if not self._check_prerequisites(prerequisites):
                return {
                    "rule_id": rule_id,
                    "status": "skipped",
                    "message": "Prerequisites not met",
                }

            if remediation.get("backup_before", False):
                try:
                    backup_file = self.create_backup(rule, backup_dir)
                    if self.logger:
                        self.logger.info(f"Created backup: {backup_file}")
                except Exception as e:
                    if self.logger:
                        self.logger.warning(f"Backup failed: {e}")

            command = remediation.get("command", "")
            timeout = remediation.get("timeout", 30)
            
            variables = {
                "hardening_value": hardening_value,
                "backup_dir": backup_dir,
            }
            
            cmd = self.substitute_variables(command, variables)
            result = self.execute_command(cmd, timeout)
            
            if result["returncode"] != 0:
                return {
                    "rule_id": rule_id,
                    "status": "fail",
                    "message": f"Remediation command failed: {result['stderr']}",
                }

            if remediation.get("verify_after", False):
                if self.verify_check(rule, hardening_level):
                    return {
                        "rule_id": rule_id,
                        "status": "success",
                        "message": "Applied and verified",
                        "requires_reboot": remediation.get("requires_reboot", False),
                    }
                else:
                    return {
                        "rule_id": rule_id,
                        "status": "fail",
                        "message": "Applied but verification failed",
                    }
            
            return {
                "rule_id": rule_id,
                "status": "success",
                "message": "Applied successfully",
                "requires_reboot": remediation.get("requires_reboot", False),
            }
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error applying rule {rule_id}: {e}")
            return {
                "rule_id": rule_id,
                "status": "error",
                "message": str(e),
            }
    
    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a PowerShell command.
        
        Args:
            command: PowerShell command
            timeout: Timeout in seconds
        
        Returns:
            Dictionary with returncode, stdout, stderr
        """
        try:
            process = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            
            return {
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
        
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
            }
    
    def _compare_values(self, current: str, expected: Any, operator: str, value_type: str) -> bool:
        """Compare current value with expected."""
        try:
            if value_type == "number":
                current_val = float(current)
                expected_val = float(expected)
                
                if operator == "==":
                    return current_val == expected_val
                elif operator == ">=":
                    return current_val >= expected_val
                elif operator == "<=":
                    return current_val <= expected_val
                elif operator == ">":
                    return current_val > expected_val
                elif operator == "<":
                    return current_val < expected_val
                elif operator == "!=":
                    return current_val != expected_val
            
            else:
                if operator == "==":
                    return current.lower() == str(expected).lower()
                elif operator == "!=":
                    return current.lower() != str(expected).lower()
                elif operator == "contains":
                    return str(expected).lower() in current.lower()
                elif operator == "regex":
                    import re
                    return re.search(str(expected), current) is not None
            
            return False
        
        except Exception as exc:
            if self.logger:
                self.logger.debug(f"Comparison failed for values '{current}' and '{expected}' using operator '{operator}': {exc}")
            return False
    
    def _check_prerequisites(self, prerequisites: list) -> bool:
        """Check if prerequisites are met."""
        for prereq in prerequisites:
            if prereq == "admin_rights":
                try:
                    import ctypes
                    import sys
                    if sys.platform == "win32":
                        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                            return False
                    else:
                        return False
                except Exception:
                    return False
        
        return True
