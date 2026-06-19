from __future__ import annotations
import json
from ..models.finding import AudienceMode, NormalizedFinding, Translation
from ..engines.risk_engine import RiskScoreResult

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.rule import Rule
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

SEVERITY_COLORS = {
    "CRITICAL": "bold red", "HIGH": "bold orange1",
    "MEDIUM": "bold yellow", "LOW": "bold green",
    "INFORMATIONAL": "bold blue", "UNKNOWN": "dim",
}

def _severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.upper(), "white")

def _risk_color(rating: str) -> str:
    r = rating.upper()
    if "CRITICAL" in r: return "bold red"
    if "HIGH" in r: return "bold orange1"
    if "MEDIUM" in r: return "bold yellow"
    if "LOW" in r: return "bold green"
    return "white"

class OutputFormatter:
    def __init__(self, no_color: bool = False):
        if RICH_AVAILABLE and not no_color:
            self.console = Console()
            self._use_rich = True
        else:
            self._use_rich = False

    def print_finding_header(self, finding: NormalizedFinding) -> None:
        if not self._use_rich:
            print(f"\n{'='*60}")
            print(f"FINDING: {finding.title}")
            print(f"Source:   {finding.source_tool or finding.source.value}")
            print(f"Severity: {finding.severity.value}")
            return
        self.console.print()
        self.console.rule("[bold]Security Finding[/bold]", style="blue")
        self.console.print()
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="dim", width=16)
        table.add_column("Value")
        sev_color = _severity_color(finding.severity.value)
        table.add_row("Title", f"[bold]{finding.title}[/bold]")
        table.add_row("Source", finding.source_tool or finding.source.value)
        table.add_row("Severity", f"[{sev_color}]{finding.severity.value}[/{sev_color}]")
        table.add_row("Type", finding.finding_type or "N/A")
        if finding.affected_asset:
            a = finding.affected_asset
            table.add_row("Asset", f"{a.resource_type}: {a.resource_name or a.resource_id}")
            if a.region:
                table.add_row("Region", a.region)
        if finding.cvss:
            table.add_row("CVSS Score", f"{finding.cvss.base_score:.1f}/10")
        if finding.cve_ids:
            table.add_row("CVE IDs", ", ".join(finding.cve_ids))
        self.console.print(table)
        self.console.print()

    def print_risk_score(self, score: RiskScoreResult) -> None:
        if not self._use_rich:
            print(f"\nRISK SCORE: {score.composite_score}/10 ({score.risk_label})")
            print(f"Method: {score.scoring_method.upper()}")
            if score.in_kev:
                print("*** IN CISA KEV - ACTIVELY EXPLOITED ***")
            if score.epss_score > 0:
                print(f"EPSS: {score.epss_percentile}% probability of exploitation in 30 days")
            print(f"Rationale: {score.risk_rationale}")
            return
        risk_color = _risk_color(score.risk_label)
        kev_line = "\n[bold red]⚠ IN CISA KEV — ACTIVELY EXPLOITED IN THE WILD[/bold red]" if score.in_kev else ""
        epss_line = f"\n[yellow]EPSS: {score.epss_percentile}% probability of exploitation in next 30 days[/yellow]" if score.epss_score > 0 else ""
        panel_content = (
            f"[{risk_color}]● {score.risk_label}  ({score.composite_score:.1f}/10)[/{risk_color}]"
            f"  [dim]scored by {score.scoring_method.upper()}[/dim]"
            f"{kev_line}{epss_line}\n\n"
            f"[dim]{score.risk_rationale}[/dim]"
        )
        self.console.print(Panel(panel_content, title="[bold]Risk Score[/bold]", border_style="blue"))

    def print_translation(self, translation: Translation, audience: AudienceMode, verbose: bool = False) -> None:
        audience_label = audience.value.replace("_", " ").title()
        if not self._use_rich:
            print(f"\n{'='*60}\n{audience_label.upper()} TRANSLATION\n{'='*60}")
            if translation.executive_summary: print(f"\nSUMMARY:\n{translation.executive_summary}")
            if translation.business_impact: print(f"\nBUSINESS IMPACT:\n{translation.business_impact}")
            if translation.threat_scenario: print(f"\nTHREAT SCENARIO:\n{translation.threat_scenario}")
            if translation.risk_rating: print(f"\nRISK RATING:\n{translation.risk_rating}")
            if translation.remediation_steps:
                print("\nREMEDIATION STEPS:")
                for i, step in enumerate(translation.remediation_steps, 1):
                    print(f"  {i}. {step}")
            return
        self.console.print()
        self.console.rule(f"[bold]{audience_label} Translation[/bold]", style="cyan")
        self.console.print()
        if translation.executive_summary:
            self.console.print(Panel(translation.executive_summary, title="[bold cyan]Summary[/bold cyan]", border_style="cyan"))
        if translation.business_impact:
            self.console.print()
            self.console.print("[bold]Business Impact[/bold]")
            self.console.print(translation.business_impact)
        if translation.threat_scenario:
            self.console.print()
            self.console.print("[bold]Threat Scenario[/bold]")
            for line in translation.threat_scenario.split(chr(10)):
                line = line.strip()
                if line:
                    self.console.print(line)
        if verbose and translation.technical_explanation:
            self.console.print()
            self.console.print("[bold]Technical Explanation[/bold]")
            self.console.print(translation.technical_explanation)
        if translation.risk_rating:
            self.console.print()
            risk_color = _risk_color(translation.risk_rating)
            self.console.print(f"[bold]Risk Rating:[/bold] [{risk_color}]{translation.risk_rating}[/{risk_color}]")
        if translation.remediation_steps:
            self.console.print()
            self.console.print("[bold]Remediation Steps[/bold]")
            for i, step in enumerate(translation.remediation_steps, 1):
                self.console.print(f"  [bold]{i}.[/bold] {step}")
        if verbose:
            if translation.terraform_example:
                self.console.print()
                self.console.print("[bold]Terraform Example[/bold]")
                self.console.print(Syntax(translation.terraform_example, "hcl", theme="monokai", line_numbers=True))
            if translation.aws_cli_example:
                self.console.print()
                self.console.print("[bold]AWS CLI Example[/bold]")
                self.console.print(Syntax(translation.aws_cli_example, "bash", theme="monokai"))
            if translation.kubernetes_example:
                self.console.print()
                self.console.print("[bold]Kubernetes Example[/bold]")
                self.console.print(Syntax(translation.kubernetes_example, "yaml", theme="monokai"))
            if translation.jira_ticket:
                self.console.print()
                self.console.print("[bold]Generated Jira Ticket[/bold]")
                self.console.print(Syntax(json.dumps(translation.jira_ticket, indent=2), "json", theme="monokai"))
        if translation.prompt_tokens:
            self.console.print()
            self.console.print(f"[dim]Model: {translation.model_used}  Tokens: {translation.prompt_tokens + translation.completion_tokens}[/dim]")

    def print_error(self, message: str) -> None:
        if self._use_rich:
            self.console.print(f"[bold red]Error:[/bold red] {message}")
        else:
            print(f"ERROR: {message}")

    def print_success(self, message: str) -> None:
        if self._use_rich:
            self.console.print(f"[bold green]✓[/bold green] {message}")
        else:
            print(f"OK: {message}")

    def print_info(self, message: str) -> None:
        if self._use_rich:
            self.console.print(f"[dim]{message}[/dim]")
        else:
            print(message)
