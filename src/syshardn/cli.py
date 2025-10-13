"""
SysHardn CLI

Main command-line interface for the system hardening tool.
"""

import sys
import click
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from syshardn.core.os_detector import OSDetector
from syshardn.parsers.rule_loader import RuleLoader
from syshardn.executors.executor_factory import ExecutorFactory
from syshardn.reporters.report_generator import ReportGenerator, ReportFormat
from syshardn.utils.logger import setup_logger, get_logger

console = Console()
logger = None


def get_rules_directory() -> Path:
    """Get the rules directory path."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        bundle_dir = Path(sys._MEIPASS)
        rules_dir = bundle_dir / "rules"
        if rules_dir.exists():
            return rules_dir
    
    pkg_dir = Path(__file__).parent.parent.parent
    rules_dir = pkg_dir / "rules"
    
    if rules_dir.exists():
        return rules_dir

    rules_dir = Path.cwd() / "rules"
    if rules_dir.exists():
        return rules_dir

    console.print("[red]Error: Rules directory not found![/red]")
    console.print("[yellow]Tried locations:[/yellow]")
    if getattr(sys, 'frozen', False):
        console.print(f"  - {Path(sys._MEIPASS) / 'rules'} (bundle)")
    console.print(f"  - {Path(__file__).parent.parent.parent / 'rules'} (package)")
    console.print(f"  - {Path.cwd() / 'rules'} (current directory)")
    console.print("\n[yellow]Tip:[/yellow] Make sure the 'rules' directory is in the same location as the executable.")
    sys.exit(1)


def get_backup_directory(custom_dir: Optional[str] = None) -> Path:
    """Get the backup directory path."""
    if custom_dir:
        return Path(custom_dir)
    
    backup_dir = Path.cwd() / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def _generate_pdf_report(results: List[dict], output: str, level: str, reporter: ReportGenerator) -> Optional[Path]:
    """Generate a PDF report using reportlab."""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from datetime import datetime
    
    output_path = Path(output).with_suffix('.pdf')
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(str(output_path), pagesize=letter,
                           rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=18)

    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=30,
        alignment=TA_CENTER
    )

    title = Paragraph(f"System Hardening Report<br/>{level.upper()} Level", title_style)
    elements.append(title)
    elements.append(Spacer(1, 0.2 * inch))

    date_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    date_para = Paragraph(date_text, styles['Normal'])
    elements.append(date_para)
    elements.append(Spacer(1, 0.3 * inch))

    total = len(results)
    passed = sum(1 for r in results if r.get('status') == 'pass')
    failed = sum(1 for r in results if r.get('status') == 'fail')
    errors = sum(1 for r in results if r.get('status') == 'error')
    compliance_rate = (passed / total * 100) if total > 0 else 0

    summary_data = [
        ['Total Rules', str(total)],
        ['Passed', str(passed)],
        ['Failed', str(failed)],
        ['Errors', str(errors)],
        ['Compliance Rate', f'{compliance_rate:.1f}%']
    ]
    
    summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(Paragraph("<b>Summary</b>", styles['Heading2']))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.2 * inch))

    severity_counts = {}
    for r in results:
        sev = r.get('severity', 'unknown').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    if severity_counts:
        severity_data = [['Severity', 'Count']]
        for sev in ['critical', 'high', 'medium', 'low', 'unknown']:
            if sev in severity_counts:
                severity_data.append([sev.capitalize(), str(severity_counts[sev])])
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(Paragraph("<b>Breakdown by Severity</b>", styles['Heading3']))
        elements.append(Spacer(1, 0.05 * inch))
        elements.append(severity_table)
    
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("<b>Detailed Results</b>", styles['Heading2']))
    elements.append(Spacer(1, 0.1 * inch))

    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontSize=7,
        leading=9,
        wordWrap='CJK'
    )
    
    results_data: List[List] = [['Rule ID', 'Category', 'Severity', 'Status', 'Description']]
    for result in results:
        rule_id = result.get('rule_id', 'N/A')
        status = result.get('status', 'unknown').upper()

        category = result.get('category', 'N/A')
        severity = result.get('severity', 'N/A')
        description = result.get('description', result.get('message', 'No description'))

        results_data.append([
            Paragraph(rule_id, cell_style),
            Paragraph(category, cell_style),
            Paragraph(severity.upper() if severity != 'N/A' else 'N/A', cell_style),
            Paragraph(status, cell_style),
            Paragraph(description, cell_style)
        ])
    
    results_table = Table(results_data, colWidths=[0.9*inch, 1.3*inch, 0.8*inch, 0.7*inch, 2.8*inch])
    results_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP')
    ]))
    
    elements.append(results_table)

    doc.build(elements)
    
    return output_path


@click.group()
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    help="Set logging level",
)
@click.option(
    "--log-file",
    type=click.Path(),
    default=None,
    help="Log file path (default: syshardn.log in current directory)",
)
@click.version_option(version="0.1.0", prog_name="SysHardn")
@click.pass_context
def cli(ctx, log_level: str, log_file: Optional[str]):
    """
    SysHardn - Multi-platform System Hardening Tool
    
    A comprehensive security hardening tool based on CIS Benchmarks
    for Windows and Linux systems.
    """
    global logger

    if log_file is None:
        log_file = "syshardn.log"
    
    setup_logger(log_level, log_file)
    logger = get_logger(__name__)

    ctx.ensure_object(dict)
    ctx.obj["log_level"] = log_level
    ctx.obj["log_file"] = log_file
    ctx.obj["rules_dir"] = get_rules_directory()


@cli.command()
@click.option(
    "--level",
    type=click.Choice(["basic", "moderate", "strict"], case_sensitive=False),
    default="moderate",
    help="Hardening level to check against",
)
@click.option(
    "--rules",
    multiple=True,
    help="Specific rule IDs to check (e.g., WIN-001, LNX-300)",
)
@click.option(
    "--category",
    help="Filter by category (e.g., 'Account Policies', 'Filesystem')",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Filter by minimum severity level",
)
@click.option(
    "--report",
    type=click.Path(),
    help="Generate report file (supports .txt, .json, .html)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show detailed output",
)
@click.pass_context
def check(
    ctx,
    level: str,
    rules: tuple,
    category: Optional[str],
    severity: Optional[str],
    report: Optional[str],
    verbose: bool,
):
    """
    Check system compliance against hardening rules.
    
    This command audits the system without making any changes.
    """
    if logger:
        logger.info(f"Starting compliance check with level: {level}")

    os_detector = OSDetector()
    os_type = os_detector.get_os_type()
    
    console.print(Panel.fit(
        f"[bold cyan]SysHardn Compliance Check[/bold cyan]\n"
        f"OS: {os_type.capitalize()}\n"
        f"Version: {os_detector.get_version()}\n"
        f"Hardening Level: {level.capitalize()}",
        border_style="cyan"
    ))

    rule_loader = RuleLoader(str(ctx.obj["rules_dir"]))
    
    if rules:
        loaded_rules = []
        for rule_id in rules:
            rule = rule_loader.load_rule_by_id(rule_id)
            if rule:
                loaded_rules.append(rule)
            else:
                console.print(f"[yellow]Warning: Rule {rule_id} not found[/yellow]")
    else:
        loaded_rules = rule_loader.load_rules(os_type=os_type)

    filtered_rules = []
    for rule in loaded_rules:
        if not os_detector.is_supported(rule.get("metadata", {})):
            continue

        if category and rule.get("rule", {}).get("category", "").lower() != category.lower():
            continue

        if severity:
            rule_severity = rule.get("rule", {}).get("severity", "low")
            severity_levels = ["low", "medium", "high", "critical"]
            if severity_levels.index(rule_severity) < severity_levels.index(severity):
                continue
        
        filtered_rules.append(rule)
    
    if not filtered_rules:
        console.print("[yellow]No rules matched the criteria[/yellow]")
        return
    
    console.print(f"\n[bold]Checking {len(filtered_rules)} rule(s)...[/bold]\n")

    executor = ExecutorFactory.create_executor(os_type)
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Checking rules...", total=len(filtered_rules))
        
        for rule in filtered_rules:
            rule_id = rule.get("rule", {}).get("id")
            description = rule.get("rule", {}).get("description", "")
            
            progress.update(task, description=f"Checking {rule_id}: {description[:50]}...")
            
            try:
                result = executor.check_rule(rule, level)
                # Add description to result for JSON reports
                result["description"] = description
                results.append(result)
                if logger:
                    logger.info(f"Checked rule {rule_id}: {result['status']}")
            except Exception as e:
                if logger:
                    logger.error(f"Error checking rule {rule_id}: {e}")
                results.append({
                    "rule_id": rule_id,
                    "status": "error",
                    "message": str(e),
                    "description": description,
                })
            
            progress.advance(task)

    _display_check_results(results, verbose)
    
    if report:
        _generate_report(results, report, os_detector, level)

    failed = sum(1 for r in results if r["status"] == "fail")
    if failed > 0:
        sys.exit(1)


@cli.command()
@click.option(
    "--level",
    type=click.Choice(["basic", "moderate", "strict"], case_sensitive=False),
    default="moderate",
    help="Hardening level to apply",
)
@click.option(
    "--rules",
    multiple=True,
    help="Specific rule IDs to apply (e.g., WIN-001, LNX-300)",
)
@click.option(
    "--category",
    help="Apply rules from specific category",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be changed without applying",
)
@click.option(
    "--force",
    is_flag=True,
    help="Skip confirmation prompts",
)
@click.option(
    "--backup-dir",
    type=click.Path(),
    default="./backups",
    help="Directory for backup files",
)
@click.pass_context
def apply(
    ctx,
    level: str,
    rules: tuple,
    category: Optional[str],
    dry_run: bool,
    force: bool,
    backup_dir: str,
):
    """
    Apply hardening rules to the system.
    
    This command makes changes to your system configuration.
    Always review changes before applying.
    """
    if logger:
        logger.info(f"Starting hardening application with level: {level}")

    if not _check_privileges():
        console.print("[red]Error: Administrator/root privileges required![/red]")
        sys.exit(1)

    os_detector = OSDetector()
    os_type = os_detector.get_os_type()
    
    console.print(Panel.fit(
        f"[bold yellow]SysHardn - Apply Hardening[/bold yellow]\n"
        f"OS: {os_type.capitalize()}\n"
        f"Version: {os_detector.get_version()}\n"
        f"Hardening Level: {level.capitalize()}\n"
        f"Mode: {'DRY RUN' if dry_run else 'APPLY'}",
        border_style="yellow"
    ))

    rule_loader = RuleLoader(str(ctx.obj["rules_dir"]))
    
    if rules:
        loaded_rules = []
        for rule_id in rules:
            rule = rule_loader.load_rule_by_id(rule_id)
            if rule:
                loaded_rules.append(rule)
    else:
        loaded_rules = rule_loader.load_rules(os_type=os_type)
    
    filtered_rules = [
        rule for rule in loaded_rules
        if os_detector.is_supported(rule.get("metadata", {}))
        and (not category or rule.get("rule", {}).get("category", "").lower() == category.lower())
    ]
    
    if not filtered_rules:
        console.print("[yellow]No rules matched the criteria[/yellow]")
        return

    console.print(f"\n[bold]Rules to apply: {len(filtered_rules)}[/bold]\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Category")
    table.add_column("Description")
    table.add_column("Severity")
    
    for rule in filtered_rules[:10]:
        rule_data = rule.get("rule", {})
        table.add_row(
            rule_data.get("id", ""),
            rule_data.get("category", ""),
            rule_data.get("description", "")[:50] + "...",
            rule_data.get("severity", ""),
        )
    
    if len(filtered_rules) > 10:
        table.add_row("...", "...", f"and {len(filtered_rules) - 10} more", "...")
    
    console.print(table)

    if not force and not dry_run:
        if not click.confirm("\nDo you want to continue?"):
            console.print("[yellow]Aborted[/yellow]")
            return

    Path(backup_dir).mkdir(parents=True, exist_ok=True)

    executor = ExecutorFactory.create_executor(os_type)
    results = []
    
    console.print(f"\n[bold]{'Simulating' if dry_run else 'Applying'} rules...[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Processing...", total=len(filtered_rules))
        
        for rule in filtered_rules:
            rule_id = rule.get("rule", {}).get("id")
            description = rule.get("rule", {}).get("description", "")
            
            progress.update(task, description=f"Processing {rule_id}...")
            
            try:
                if dry_run:
                    result = {"rule_id": rule_id, "status": "dry_run", "message": "Would apply"}
                else:
                    result = executor.apply_rule(rule, level, backup_dir)
                
                results.append(result)
                if logger:
                    logger.info(f"Applied rule {rule_id}: {result['status']}")
            except Exception as e:
                if logger:
                    logger.error(f"Error applying rule {rule_id}: {e}")
                results.append({
                    "rule_id": rule_id,
                    "status": "error",
                    "message": str(e),
                })
            
            progress.advance(task)

    _display_apply_results(results, dry_run)

    needs_reboot = any(r.get("requires_reboot", False) for r in results)
    if needs_reboot and not dry_run:
        console.print("\n[bold yellow]System reboot required for some changes to take effect[/bold yellow]")


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["text", "json", "html", "csv", "markdown", "pdf"], case_sensitive=False),
    default="text",
    help="Report format",
)
@click.option(
    "--output",
    type=click.Path(),
    required=True,
    help="Output file path",
)
@click.option(
    "--level",
    type=click.Choice(["basic", "moderate", "strict"], case_sensitive=False),
    default="moderate",
    help="Hardening level for the report",
)
@click.pass_context
def report(ctx, format: str, output: str, level: str):
    """
    Generate a compliance report.
    
    This runs a check and generates a formatted report.
    Supported formats: text (console), json, html, csv, markdown, pdf
    """
    if logger:
        logger.info(f"Generating {format} report")
    
    console.print(f"[bold]Generating {format.upper()} report...[/bold]")

    os_detector = OSDetector()
    os_type = os_detector.get_os_type()

    rule_loader = RuleLoader(str(ctx.obj["rules_dir"]))
    loaded_rules = rule_loader.load_rules(os_type=os_type)
    
    filtered_rules = [
        rule for rule in loaded_rules
        if os_detector.is_supported(rule.get("metadata", {}))
    ]

    executor = ExecutorFactory.create_executor(os_type)
    results = []
    
    for rule in filtered_rules:
        try:
            result = executor.check_rule(rule, level)
            rule_data = rule.get("rule", {})
            result["category"] = rule_data.get("category", "N/A")
            result["severity"] = rule_data.get("severity", "N/A")
            result["description"] = rule_data.get("description", result.get("message", "N/A"))
            results.append(result)
        except Exception as e:
            if logger:
                logger.error(f"Error checking rule: {e}")

    reporter = ReportGenerator()
    format_map = {
        "text": ReportFormat.CONSOLE,
        "json": ReportFormat.JSON,
        "html": ReportFormat.HTML,
        "csv": ReportFormat.CSV,
        "markdown": ReportFormat.MARKDOWN,
        "pdf": ReportFormat.HTML 
    }
    report_format = format_map.get(format.lower(), ReportFormat.CONSOLE)
    output_path = None if report_format == ReportFormat.CONSOLE else Path(output)

    if format.lower() == "pdf":
        try:
            result_path = _generate_pdf_report(results, output, level, reporter)
            if result_path:
                console.print(f"[green]✓ PDF report generated: {result_path}[/green]")
                return
        except ImportError:
            console.print("[yellow]Warning: reportlab not installed. Generating HTML instead.[/yellow]")
            console.print("[dim]Install with: pip install reportlab[/dim]")
            report_format = ReportFormat.HTML
            output_path = Path(output).with_suffix('.html')
        except Exception as e:
            console.print(f"[yellow]Warning: PDF generation failed ({e}). Generating HTML instead.[/yellow]")
            report_format = ReportFormat.HTML
            output_path = Path(output).with_suffix('.html')
    
    result_path = reporter.generate(results, report_format, output_path, f"System Hardening Report - {level.upper()}")
    
    if result_path:
        console.print(f"[green]✓ Report generated: {result_path}[/green]")
    else:
        console.print("[green]Report displayed above[/green]")


@cli.command()
@click.option(
    "--backup-dir",
    type=click.Path(exists=True),
    default="backups",
    help="Backup directory (default: backups/)",
)
@click.option(
    "--rule-id",
    help="Specific rule ID to rollback (e.g., LNX-001)",
)
@click.option(
    "--list",
    "list_backups",
    is_flag=True,
    help="List available backups",
)
@click.option(
    "--latest",
    is_flag=True,
    help="Rollback the latest backup for specified rule",
)
@click.option(
    "--force",
    is_flag=True,
    help="Skip confirmation prompts",
)
@click.pass_context
def rollback(ctx, backup_dir: str, rule_id: Optional[str], list_backups: bool, latest: bool, force: bool):
    """
    Rollback applied hardening rules using backups.
    
    Restore system to previous state before hardening was applied.
    """
    import json
    from datetime import datetime
    
    backup_path = Path(backup_dir)
    
    if not backup_path.exists():
        console.print(f"[red]Backup directory not found: {backup_dir}[/red]")
        sys.exit(1)

    if list_backups:
        backup_files = sorted(backup_path.glob("*.json"), reverse=True)
        
        if not backup_files:
            console.print(f"[yellow]No backups found in {backup_dir}/[/yellow]")
            return
        
        console.print(f"\n[bold]Available Backups in {backup_dir}/:[/bold]\n")
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Timestamp")
        table.add_column("Backup File")
        
        for backup_file in backup_files:
            try:
                with open(backup_file, 'r') as f:
                    metadata = json.load(f)
                
                rule_id_str = metadata.get("rule_id", "unknown")
                timestamp = metadata.get("timestamp", "unknown")
                
                table.add_row(
                    rule_id_str,
                    timestamp,
                    backup_file.stem
                )
            except Exception as e:
                console.print(f"[yellow]Warning: Could not read {backup_file.name}: {e}[/yellow]")
        
        console.print(table)
        console.print(f"\n[bold]Total: {len(backup_files)} backup(s)[/bold]")
        console.print("\n[yellow]To rollback, use: syshardn rollback --rule-id <RULE_ID> --latest[/yellow]")
        return

    if not rule_id:
        console.print("[red]Error: --rule-id required for rollback (or use --list to see available backups)[/red]")
        sys.exit(1)

    backup_files = sorted(backup_path.glob(f"{rule_id}_*.json"), reverse=True)
    
    if not backup_files:
        console.print(f"[red]No backups found for rule {rule_id}[/red]")
        sys.exit(1)

    if latest or len(backup_files) == 1:
        selected_backup = backup_files[0]
    else:
        console.print(f"\n[bold]Multiple backups found for {rule_id}:[/bold]\n")
        for idx, backup_file in enumerate(backup_files, 1):
            console.print(f"  {idx}. {backup_file.name}")
        
        choice = click.prompt("\nSelect backup number to rollback", type=int, default=1)
        if choice < 1 or choice > len(backup_files):
            console.print("[red]Invalid choice[/red]")
            sys.exit(1)
        selected_backup = backup_files[choice - 1]

    try:
        with open(selected_backup, 'r') as f:
            metadata = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading backup metadata: {e}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]Rollback Details:[/bold]")
    console.print(f"  Rule ID: {metadata.get('rule_id')}")
    console.print(f"  Timestamp: {metadata.get('timestamp')}")
    console.print(f"  Backup file: {selected_backup.name}")
    console.print()
    
    if not force:
        if not click.confirm(click.style("Do you want to proceed with rollback?", fg="yellow"), default=False):
            console.print("[yellow]Rollback cancelled[/yellow]")
            return

        if not _check_privileges():
            console.print("[yellow]Warning: Rollback typically requires root/admin privileges[/yellow]")
            if not click.confirm(click.style("Continue anyway?", fg="yellow"), default=False):
                return
    else:
        if not _check_privileges():
            console.print("[yellow]Warning: Rollback typically requires root/admin privileges[/yellow]")

    console.print("\n[bold]Performing rollback...[/bold]\n")
    
    try:
        rule = metadata.get("rule", {})
        backup_location = str(selected_backup).replace(".json", ".backup")

        os_detector = OSDetector()
        os_type = os_detector.get_os_type()
        executor = ExecutorFactory.create_executor(os_type)

        executor.rollback_from_backup(backup_location)
        
        console.print(f"[green]✓ Successfully rolled back {rule_id}[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ Rollback failed: {e}[/red]")
        if logger:
            logger.exception(f"Rollback failed for {rule_id}")
        sys.exit(1)


@cli.command()
@click.option(
    "--os-filter",
    type=click.Choice(["windows", "linux"], case_sensitive=False),
    help="Filter by operating system",
)
@click.option(
    "--category",
    help="Filter by category",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    help="Filter by severity",
)
@click.option(
    "--detailed",
    is_flag=True,
    help="Show detailed rule information",
)
@click.pass_context
def list_rules(ctx, os_filter: Optional[str], category: Optional[str], severity: Optional[str], detailed: bool):
    """
    List available hardening rules.
    
    Display all rules or filter by OS, category, or severity.
    """
    rule_loader = RuleLoader(str(ctx.obj["rules_dir"]))

    loaded_rules = rule_loader.load_rules(os_type=os_filter)

    filtered_rules = []
    for rule in loaded_rules:
        rule_data = rule.get("rule", {})
        
        if category and rule_data.get("category", "").lower() != category.lower():
            continue
        
        if severity and rule_data.get("severity", "").lower() != severity.lower():
            continue
        
        filtered_rules.append(rule)

    if detailed:
        for rule in filtered_rules:
            _display_detailed_rule(rule)
    else:
        _display_rules_table(filtered_rules)
    
    console.print(f"\n[bold]Total: {len(filtered_rules)} rule(s)[/bold]")


def _check_privileges() -> bool:
    """Check if running with admin/root privileges."""
    import os
    
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def _display_check_results(results: List[dict], verbose: bool):
    """Display check results in a formatted table."""
    # Always show description column for both Windows and Linux
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Status")
    table.add_column("Description", style="dim")
    table.add_column("Message")
    
    passed = failed = errors = 0
    
    for result in results:
        status = result["status"]
        rule_id = result.get("rule_id", "Unknown")
        message = result.get("message", "")
        description = result.get("description", "")
        
        if status == "pass":
            status_str = "[green]✓ PASS[/green]"
            passed += 1
        elif status == "fail":
            status_str = "[red]✗ FAIL[/red]"
            failed += 1
        else:
            status_str = "[yellow]⚠ ERROR[/yellow]"
            errors += 1
        
        # Truncate description if too long
        desc_truncated = description[:50] + "..." if len(description) > 50 else description
        
        if verbose or status != "pass":
            # Always use 4 columns: Rule ID, Status, Description, Message
            table.add_row(rule_id, status_str, desc_truncated if description else "-", message[:80])
    
    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] {passed} passed, {failed} failed, {errors} errors")


def _display_apply_results(results: List[dict], dry_run: bool):
    """Display apply results."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Status")
    table.add_column("Message")
    
    success = failed = skipped = 0
    
    for result in results:
        status = result["status"]
        rule_id = result.get("rule_id", "Unknown")
        message = result.get("message", "")
        
        if status in ["success", "dry_run"]:
            status_str = "[green]✓ SUCCESS[/green]" if not dry_run else "[blue]○ DRY RUN[/blue]"
            success += 1
        elif status == "skipped":
            status_str = "[yellow]- SKIPPED[/yellow]"
            skipped += 1
        else:
            status_str = "[red]✗ FAILED[/red]"
            failed += 1
        
        table.add_row(rule_id, status_str, message[:80])
    
    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] {success} applied, {failed} failed, {skipped} skipped")


def _display_rules_table(rules: List[dict]):
    """Display rules in a table format."""
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Rule ID", style="cyan")
    table.add_column("OS")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Description")
    
    for rule in rules:
        metadata = rule.get("metadata", {})
        rule_data = rule.get("rule", {})
        
        table.add_row(
            rule_data.get("id", ""),
            metadata.get("os", "").upper(),
            rule_data.get("category", ""),
            rule_data.get("severity", ""),
            rule_data.get("description", "")[:60] + "...",
        )
    
    console.print(table)


def _display_detailed_rule(rule: dict):
    """Display detailed rule information."""
    metadata = rule.get("metadata", {})
    rule_data = rule.get("rule", {})
    
    console.print(Panel.fit(
        f"[bold cyan]{rule_data.get('id')}[/bold cyan]: {rule_data.get('description')}\n\n"
        f"[bold]Category:[/bold] {rule_data.get('category')} / {rule_data.get('subcategory', 'N/A')}\n"
        f"[bold]Severity:[/bold] {rule_data.get('severity', 'unknown').upper()}\n"
        f"[bold]OS:[/bold] {metadata.get('os', 'unknown').upper()}\n"
        f"[bold]CIS Reference:[/bold] {rule_data.get('audit', {}).get('cis_reference', 'N/A')}\n"
        f"[bold]Rationale:[/bold] {rule_data.get('audit', {}).get('rationale', 'N/A')[:200]}...",
        border_style="cyan"
    ))


def _generate_report(results: List[dict], report_path: str, os_detector: OSDetector, level: str):
    """Generate a report file."""
    ext = Path(report_path).suffix.lower()
    format_map = {".txt": ReportFormat.MARKDOWN, ".json": ReportFormat.JSON, ".html": ReportFormat.HTML, ".md": ReportFormat.MARKDOWN}
    format_type = format_map.get(ext, ReportFormat.MARKDOWN)
    
    reporter = ReportGenerator()
    output_file = reporter.generate(results, format_type, Path(report_path), f"System Hardening Report - {level.upper()}")
    console.print(f"\n[green]Report saved to: {output_file}[/green]")


def main():
    """Entry point for the CLI."""
    try:
        cli()  
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except click.Abort:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        if logger:
            logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
