"""
YAML Rule Parser

Loads and validates security hardening rules from YAML files.
"""

import os
import glob
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from rich.console import Console

console = Console()


class RuleLoader:
    """Loads and parses YAML rule files."""

    def __init__(self, rules_dir: str):
        """
        Initialize RuleLoader.

        Args:
            rules_dir: Path to the rules directory
        """
        self.rules_dir = Path(rules_dir)
        if not self.rules_dir.exists():
            raise ValueError(f"Rules directory not found: {rules_dir}")

    def load_rule(self, rule_file: str) -> Dict[str, Any]:
        """
        Load a single rule from a YAML file.

        Args:
            rule_file: Path to the rule file

        Returns:
            Parsed rule as dictionary

        Raises:
            ValueError: If rule file is invalid
        """
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)

            if not isinstance(rule_data, dict):
                raise ValueError("Rule file must contain a dictionary")

            if "metadata" not in rule_data:
                raise ValueError("Rule missing 'metadata' section")

            if "rule" not in rule_data:
                raise ValueError("Rule missing 'rule' section")

            rule_id = rule_data.get("rule", {}).get("id", "unknown")
            has_check = "check" in rule_data
            check_has_command = rule_data.get("check", {}).get("command", "") != "" if has_check else False
            console.print(f"[dim]Loaded {rule_id}: has_check={has_check}, has_command={check_has_command}[/dim]")

            rule_data["_file_path"] = str(rule_file)

            return rule_data

        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {rule_file}: {e}")
        except Exception as e:
            raise ValueError(f"Error loading rule {rule_file}: {e}")

    def load_rules(
        self, os_type: Optional[str] = None, rule_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Load multiple rules based on filters.

        Args:
            os_type: Filter by OS ('windows', 'linux', 'macos', or 'darwin')
            rule_ids: Filter by specific rule IDs

        Returns:
            List of parsed rules
        """
        rules = []

        if os_type == "windows":
            patterns = [
                str(self.rules_dir / "windows" / "WIN-*.yaml"),
                str(self.rules_dir / "windows" / "TEST-*.yaml"),
            ]
        elif os_type in ["linux", "macos", "darwin"]:
            os_dir = "linux" if os_type in ["linux", "macos", "darwin"] else os_type
            patterns = [
                str(self.rules_dir / os_dir / "LNX-*.yaml"),
                str(self.rules_dir / os_dir / "TEST-*.yaml"),
            ]
        else:
            patterns = [
                str(self.rules_dir / "windows" / "WIN-*.yaml"),
                str(self.rules_dir / "windows" / "TEST-*.yaml"),
                str(self.rules_dir / "linux" / "LNX-*.yaml"),
                str(self.rules_dir / "linux" / "TEST-*.yaml"),
            ]

        rule_files = []
        for p in patterns:
            rule_files.extend(glob.glob(p))

        for rule_file in sorted(rule_files):
            try:
                rule = self.load_rule(rule_file)

                if rule_ids:
                    rule_id = rule.get("rule", {}).get("id")
                    if rule_id not in rule_ids:
                        continue

                rules.append(rule)

            except Exception as e:
                console.print(f"[yellow]Warning: Failed to load {rule_file}: {e}[/yellow]")

        return rules

    def load_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a specific rule by its ID.

        Args:
            rule_id: Rule ID (e.g., 'WIN-001', 'LNX-300')

        Returns:
            Parsed rule or None if not found
        """
        if rule_id.startswith("WIN"):
            os_type = "windows"
        elif rule_id.startswith("LNX"):
            os_type = "linux"
        else:
            raise ValueError(f"Invalid rule ID format: {rule_id}")

        rules = self.load_rules(os_type=os_type)

        for rule in rules:
            if rule.get("rule", {}).get("id") == rule_id:
                return rule

        return None

    def get_rule_value(
        self, rule: Dict[str, Any], hardening_level: str = "moderate"
    ) -> Any:
        """
        Get the hardening value for a specific level.

        Args:
            rule: Rule dictionary
            hardening_level: 'basic', 'moderate', or 'strict'

        Returns:
            Hardening value for the specified level
        """
        levels = rule.get("rule", {}).get("hardening_levels", {})
        level_config = levels.get(hardening_level, {})

        if not level_config.get("enabled", False):
            return None

        return level_config.get("value")

    def substitute_variables(
        self, command: str, variables: Dict[str, Any]
    ) -> str:
        """
        Substitute template variables in commands.

        Args:
            command: Command string with {{variables}}
            variables: Dictionary of variable values

        Returns:
            Command with substituted values
        """
        result = command
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))
        return result

    def validate_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Validate rule structure and required fields.

        Args:
            rule: Rule dictionary

        Returns:
            True if valid, False otherwise
        """
        required_fields = {
            "metadata": ["benchmark", "os"],
            "rule": ["id", "category", "description", "severity"],
        }

        try:
            for section, fields in required_fields.items():
                if section not in rule:
                    console.print(f"[red]Missing section: {section}[/red]")
                    return False

                for field in fields:
                    if field not in rule[section]:
                        console.print(f"[red]Missing field: {section}.{field}[/red]")
                        return False

            return True

        except Exception as e:
            console.print(f"[red]Validation error: {e}[/red]")
            return False
