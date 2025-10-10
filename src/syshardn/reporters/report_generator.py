"""
Report Generator for SysHardn.

Generates compliance reports in various formats (console, JSON, HTML, CSV).
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress


class ReportFormat(Enum):
    """Supported report formats."""
    CONSOLE = "console"
    JSON = "json"
    HTML = "html"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportGenerator:
    """
    Generates compliance reports from check results.
    
    Supports multiple output formats including console, JSON, HTML, CSV, and Markdown.
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the ReportGenerator.
        
        Args:
            output_dir: Directory to save reports (default: ./reports)
        """
        self.console = Console()
        self.output_dir = output_dir or Path.cwd() / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(
        self,
        results: List[Dict[str, Any]],
        format: ReportFormat = ReportFormat.CONSOLE,
        output_file: Optional[Path] = None,
        title: str = "System Hardening Compliance Report"
    ) -> Optional[Path]:
        """
        Generate a compliance report.
        
        Args:
            results: List of check results from executors
            format: Output format
            output_file: Optional output file path
            title: Report title
            
        Returns:
            Path to generated report file, or None for console output
        """
        if format == ReportFormat.CONSOLE:
            return self._generate_console_report(results, title)
        elif format == ReportFormat.JSON:
            return self._generate_json_report(results, output_file, title)
        elif format == ReportFormat.HTML:
            return self._generate_html_report(results, output_file, title)
        elif format == ReportFormat.CSV:
            return self._generate_csv_report(results, output_file)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report(results, output_file, title)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_console_report(
        self,
        results: List[Dict[str, Any]],
        title: str
    ) -> None:
        """Generate a console report with rich formatting."""
        total = len(results)
        passed = sum(1 for r in results if r.get('status') == 'pass')
        failed = sum(1 for r in results if r.get('status') == 'fail')
        errors = sum(1 for r in results if r.get('status') == 'error')

        self.console.print()
        self.console.print(Panel.fit(
            f"[bold cyan]{title}[/bold cyan]\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan"
        ))

        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value", justify="right")
        
        summary_table.add_row("Total Rules Checked:", str(total))
        summary_table.add_row("✓ Passed:", f"[green]{passed}[/green]")
        summary_table.add_row("✗ Failed:", f"[red]{failed}[/red]")
        summary_table.add_row("⚠ Errors:", f"[yellow]{errors}[/yellow]")
        
        if total > 0:
            compliance_rate = (passed / total) * 100
            color = "green" if compliance_rate >= 80 else "yellow" if compliance_rate >= 60 else "red"
            summary_table.add_row(
                "Compliance Rate:",
                f"[{color}]{compliance_rate:.1f}%[/{color}]"
            )
        
        self.console.print(Panel(summary_table, title="Summary", border_style="blue"))
        self.console.print()

        if results:
            self._display_detailed_results(results)
        
        return None
    
    def _display_detailed_results(self, results: List[Dict[str, Any]]) -> None:
        """Display detailed results table."""
        table = Table(title="Detailed Results", show_lines=True)
        
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Title", style="white")
        table.add_column("Level", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")
        
        for result in results:
            rule_id = result.get('rule_id', 'N/A')
            title = result.get('title', 'N/A')
            level = result.get('level', 'N/A').upper()

            status_value = result.get('status', 'unknown')
            if status_value == 'error':
                status = "[yellow]⚠ ERROR[/yellow]"
                details = result.get('message', 'Error occurred')
            elif status_value == 'pass':
                status = "[green]✓ PASS[/green]"
                details = result.get('message', 'Compliant')
            elif status_value == 'fail':
                status = "[red]✗ FAIL[/red]"
                details = result.get('message', 'Not compliant')
            else:
                status = "[dim]SKIP[/dim]"
                details = result.get('message', 'Skipped')

            level_colored = self._color_level(level)
            
            table.add_row(rule_id, title, level_colored, status, details)
        
        self.console.print(table)
    
    def _color_level(self, level: str) -> str:
        """Apply color to severity level."""
        level_upper = level.upper()
        if level_upper == 'L1':
            return "[yellow]L1[/yellow]"
        elif level_upper == 'L2':
            return "[red]L2[/red]"
        else:
            return level
    
    def _generate_json_report(
        self,
        results: List[Dict[str, Any]],
        output_file: Optional[Path],
        title: str
    ) -> Path:
        """Generate a JSON report."""
        report_data = {
            "title": title,
            "generated": datetime.now().isoformat(),
            "summary": self._calculate_summary(results),
            "results": results
        }
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"compliance_report_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        self.console.print(f"[green]✓[/green] JSON report saved to: {output_file}")
        return output_file
    
    def _generate_html_report(
        self,
        results: List[Dict[str, Any]],
        output_file: Optional[Path],
        title: str
    ) -> Path:
        """Generate an HTML report."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"compliance_report_{timestamp}.html"
        
        summary = self._calculate_summary(results)
        html_content = self._build_html_report(title, summary, results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.console.print(f"[green]✓[/green] HTML report saved to: {output_file}")
        return output_file
    
    def _generate_csv_report(
        self,
        results: List[Dict[str, Any]],
        output_file: Optional[Path]
    ) -> Path:
        """Generate a CSV report."""
        import csv
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"compliance_report_{timestamp}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'rule_id', 'title', 'description', 'level', 
                'status', 'message', 'current_value', 'expected_value'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                status_value = result.get('status', 'unknown')
                status_text = status_value.upper()
                
                row = {
                    'rule_id': result.get('rule_id', ''),
                    'title': result.get('title', ''),
                    'description': result.get('description', ''),
                    'level': result.get('level', ''),
                    'status': status_text,
                    'message': result.get('message', ''),
                    'current_value': result.get('current_value', ''),
                    'expected_value': result.get('expected_value', '')
                }
                writer.writerow(row)
        
        self.console.print(f"[green]✓[/green] CSV report saved to: {output_file}")
        return output_file
    
    def _generate_markdown_report(
        self,
        results: List[Dict[str, Any]],
        output_file: Optional[Path],
        title: str
    ) -> Path:
        """Generate a Markdown report."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"compliance_report_{timestamp}.md"
        
        summary = self._calculate_summary(results)
        md_content = self._build_markdown_report(title, summary, results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        self.console.print(f"[green]✓[/green] Markdown report saved to: {output_file}")
        return output_file
    
    def _calculate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate summary statistics."""
        total = len(results)
        passed = sum(1 for r in results if r.get('status') == 'pass')
        failed = sum(1 for r in results if r.get('status') == 'fail')
        errors = sum(1 for r in results if r.get('status') == 'error')
        
        compliance_rate = (passed / total * 100) if total > 0 else 0
        
        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'compliance_rate': round(compliance_rate, 2)
        }
    
    def _build_html_report(
        self,
        title: str,
        summary: Dict[str, Any],
        results: List[Dict[str, Any]]
    ) -> str:
        """Build HTML report content."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            margin: 0;
        }}
        .passed {{ color: #10b981; }}
        .failed {{ color: #ef4444; }}
        .errors {{ color: #f59e0b; }}
        .compliance {{ color: #667eea; }}
        
        .results-table {{
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .status {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .status-pass {{
            background: #d1fae5;
            color: #065f46;
        }}
        .status-fail {{
            background: #fee2e2;
            color: #991b1b;
        }}
        .status-error {{
            background: #fef3c7;
            color: #92400e;
        }}
        .level-l1 {{
            color: #f59e0b;
            font-weight: 600;
        }}
        .level-l2 {{
            color: #ef4444;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Rules</h3>
            <p class="value">{summary['total']}</p>
        </div>
        <div class="summary-card">
            <h3>Passed</h3>
            <p class="value passed">{summary['passed']}</p>
        </div>
        <div class="summary-card">
            <h3>Failed</h3>
            <p class="value failed">{summary['failed']}</p>
        </div>
        <div class="summary-card">
            <h3>Errors</h3>
            <p class="value errors">{summary['errors']}</p>
        </div>
        <div class="summary-card">
            <h3>Compliance Rate</h3>
            <p class="value compliance">{summary['compliance_rate']}%</p>
        </div>
    </div>
    
    <div class="results-table">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Level</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in results:
            rule_id = result.get('rule_id', 'N/A')
            title = result.get('title', 'N/A')
            level = result.get('level', 'N/A').upper()
            
            status_value = result.get('status', 'unknown')
            if status_value == 'error':
                status = '<span class="status status-error">⚠ ERROR</span>'
                details = result.get('message', 'Error occurred')
            elif status_value == 'pass':
                status = '<span class="status status-pass">✓ PASS</span>'
                details = result.get('message', 'Compliant')
            elif status_value == 'fail':
                status = '<span class="status status-fail">✗ FAIL</span>'
                details = result.get('message', 'Not compliant')
            else:
                status = '<span class="status status-skip">SKIP</span>'
                details = result.get('message', 'Skipped')
            
            level_class = f'level-{level.lower()}' if level in ['L1', 'L2'] else ''
            
            html += f"""
                <tr>
                    <td><code>{rule_id}</code></td>
                    <td>{title}</td>
                    <td class="{level_class}">{level}</td>
                    <td>{status}</td>
                    <td>{details}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html
    
    def _build_markdown_report(
        self,
        title: str,
        summary: Dict[str, Any],
        results: List[Dict[str, Any]]
    ) -> str:
        """Build Markdown report content."""
        md = f"""# {title}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

| Metric | Value |
|--------|-------|
| Total Rules | {summary['total']} |
| ✓ Passed | {summary['passed']} |
| ✗ Failed | {summary['failed']} |
| ⚠ Errors | {summary['errors']} |
| Compliance Rate | {summary['compliance_rate']}% |

## Detailed Results

| ID | Title | Level | Status | Details |
|----|-------|-------|--------|---------|
"""
        
        for result in results:
            rule_id = result.get('rule_id', 'N/A')
            title = result.get('title', 'N/A')
            level = result.get('level', 'N/A').upper()
            
            if result.get('error'):
                status = '⚠ ERROR'
                details = result.get('error', '')
            elif result.get('compliant'):
                status = '✓ PASS'
                details = result.get('message', 'Compliant')
            else:
                status = '✗ FAIL'
                details = result.get('message', 'Not compliant')
            
            md += f"| `{rule_id}` | {title} | {level} | {status} | {details} |\n"
        
        return md
    
    def generate_remediation_report(
        self,
        results: List[Dict[str, Any]],
        format: ReportFormat = ReportFormat.CONSOLE,
        output_file: Optional[Path] = None
    ) -> Optional[Path]:
        """
        Generate a remediation report showing what actions were taken.
        
        Args:
            results: List of remediation results
            format: Output format
            output_file: Optional output file path
            
        Returns:
            Path to generated report file, or None for console output
        """
        return self.generate(
            results,
            format=format,
            output_file=output_file,
            title="System Hardening Remediation Report"
        )
