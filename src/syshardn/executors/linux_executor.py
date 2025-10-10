"""
Linux Executor

Executes checks and remediations on Linux systems.
"""

import subprocess
from typing import Dict, Any
from syshardn.executors.base_executor import BaseExecutor


class LinuxExecutor(BaseExecutor):
    """Executor for Linux systems."""
    
    def __init__(self):
        """Initialize Linux executor."""
        super().__init__()
    
    def check_rule(self, rule: Dict[str, Any], hardening_level: str) -> Dict[str, Any]:
        """
        Check if a Linux rule is compliant.
        
        Args:
            rule: Rule dictionary
            hardening_level: Hardening level
        
        Returns:
            Result dictionary
        """
        rule_id = rule.get("rule", {}).get("id")
        
        try:
            check = rule.get("check", {})
            command = check.get("command", "")
            expected = check.get("expected", {})
            timeout = check.get("timeout", 30)

            if self.logger:
                self.logger.info(f"Rule {rule_id} - Raw command from YAML: '{command[:200] if command else 'EMPTY'}'")
                self.logger.info(f"Rule {rule_id} - Check config keys: {list(check.keys())}")

            hardening_value = self.get_hardening_value(rule, hardening_level)
            if hardening_value is None:
                return {
                    "rule_id": rule_id,
                    "status": "skipped",
                    "message": f"Rule not enabled for {hardening_level} level",
                }

            variables = {"hardening_value": hardening_value}
            cmd = self.substitute_variables(command, variables)

            if self.logger:
                self.logger.info(f"Rule {rule_id} - Final command after substitution: '{cmd[:200] if cmd else 'EMPTY'}'")

            result = self.execute_command(cmd, timeout)

            if self.logger:
                self.logger.info(f"Rule {rule_id} - Executed check command")
                self.logger.info(f"Rule {rule_id} - Return code: {result['returncode']}")
                self.logger.info(f"Rule {rule_id} - Stdout length: {len(result['stdout'])} chars")
                self.logger.info(f"Rule {rule_id} - Stdout: '{result['stdout'][:500]}'")
                self.logger.info(f"Rule {rule_id} - Stderr: '{result['stderr'][:500]}'")
            
            current_value = result["stdout"].strip()

            if not current_value:
                error_details = []
                error_details.append(f"No output from check command")
                error_details.append(f"Return code: {result['returncode']}")
                if result['stderr']:
                    error_details.append(f"Stderr: {result['stderr'][:200]}")
                error_details.append(f"Command was: {cmd[:200]}")
                
                error_msg = " | ".join(error_details)
                
                if self.logger:
                    self.logger.warning(f"Rule {rule_id} - {error_msg}")

                if result["returncode"] == 0:
                    return {
                        "rule_id": rule_id,
                        "status": "error",
                        "message": f"Check command returned no output (exit 0)",
                        "current_value": None,
                    }
                else:
                    return {
                        "rule_id": rule_id,
                        "status": "error",
                        "message": error_msg,
                        "current_value": None,
                    }

            is_compliant = self._compare_values(
                current_value,
                hardening_value,
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
                    "message": f"Non-compliant (current: {current_value}, expected: {hardening_value})",
                    "current_value": current_value,
                    "expected_value": hardening_value,
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
        Apply a Linux hardening rule.
        
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
                    "message": "Prerequisites not met (root access required)",
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
                    "status": "failed",
                    "message": f"Remediation command failed: {result['stderr']}",
                }

            if remediation.get("verify_after", False):
                import time
                time.sleep(5)

                verify_result = self.check_rule(rule, hardening_level)
                
                if verify_result.get("status") == "pass":
                    return {
                        "rule_id": rule_id,
                        "status": "success",
                        "message": "Applied and verified",
                        "requires_reboot": remediation.get("requires_reboot", False),
                    }
                else:
                    verify_msg = verify_result.get("message", "unknown reason")
                    return {
                        "rule_id": rule_id,
                        "status": "warning",
                        "message": f"Applied successfully but verification failed: {verify_msg}",
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
        Execute a bash command.
        
        Args:
            command: Bash command/script
            timeout: Timeout in seconds
        
        Returns:
            Dictionary with returncode, stdout, stderr
        """
        try:
            import os
            import tempfile

            env = os.environ.copy()
            system_paths = [
                "/usr/local/sbin",
                "/usr/local/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin",
            ]
            current_path = env.get("PATH", "")
            env["PATH"] = ":".join(system_paths + [current_path])
            
            if "LD_LIBRARY_PATH" in env:
                del env["LD_LIBRARY_PATH"]
            if "LD_PRELOAD" in env:
                del env["LD_PRELOAD"]
            
            if any(pkg_mgr in command for pkg_mgr in ['apt-get', 'apt', 'yum', 'dnf', 'zypper', 'pacman']):
                clean_env = {
                    'PATH': ':'.join(system_paths),
                    'HOME': env.get('HOME', '/root'),
                    'USER': env.get('USER', 'root'),
                    'LOGNAME': env.get('LOGNAME', 'root'),
                    'SHELL': env.get('SHELL', '/bin/bash'),
                    'TERM': env.get('TERM', 'xterm'),
                    'LANG': env.get('LANG', 'C.UTF-8'),
                }
                env = clean_env

            bash_path = "/bin/bash"
            if not os.path.exists(bash_path):
                bash_path = "/usr/bin/bash"
                if not os.path.exists(bash_path):
                    bash_path = "bash"

            if "\n" in command and ("if " in command or "for " in command or "while " in command):
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
                    f.write("#!/bin/bash\n")
                    f.write("set -o pipefail\n") 
                    f.write(command)
                    temp_script = f.name
                
                try:
                    os.chmod(temp_script, 0o700)
                    process = subprocess.run(
                        [bash_path, temp_script],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=timeout,
                        env=env,
                    )
                    
                    stdout_val = process.stdout if process.stdout is not None else ""
                    stderr_val = process.stderr if process.stderr is not None else ""
                    
                    return {
                        "returncode": process.returncode,
                        "stdout": stdout_val,
                        "stderr": stderr_val,
                    }
                finally:
                    try:
                        os.unlink(temp_script)
                    except:
                        pass
            else:
                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True,
                    executable=bash_path,
                    timeout=timeout,
                    env=env,
                )
                
                stdout_val = process.stdout if process.stdout is not None else ""
                stderr_val = process.stderr if process.stderr is not None else ""
                
                return {
                    "returncode": process.returncode,
                    "stdout": stdout_val,
                    "stderr": stderr_val,
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
                "stderr": f"Exception: {str(e)}",
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
        
        except Exception:
            return False
    
    def _check_prerequisites(self, prerequisites: list) -> bool:
        """Check if prerequisites are met."""
        import os
        
        for prereq in prerequisites:
            if prereq == "root_access":
                if os.geteuid() != 0:
                    return False
        
        return True
