import json
import os
import sys
from pathlib import Path
from typing import Optional
import click

def _get_modules():
    from cli.src.models.finding import AudienceMode
    from cli.src.parsers.base import ParserFactory
    from cli.src.engines.risk_engine import RiskContext, prioritize_findings, score_finding
    from cli.src.engines.translation_engine import TranslationEngine
    from cli.src.utils.formatter import OutputFormatter
    return AudienceMode, ParserFactory, RiskContext, prioritize_findings, score_finding, TranslationEngine, OutputFormatter

AUDIENCE_CHOICES = ["executive","manager","developer","security_analyst","soc_analyst","devsecops","grc"]

@click.group()
@click.version_option(version="0.1.0", prog_name="translate")
def cli():
    """Security Findings Translator — translate findings into clear audience-appropriate language."""
    pass

@cli.command("finding")
@click.argument("input_file", type=click.Path(allow_dash=True))
@click.option("--audience", "-a", type=click.Choice(AUDIENCE_CHOICES), multiple=True, default=["security_analyst"])
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--score-only", is_flag=True, default=False)
@click.option("--format", "output_format", type=click.Choice(["terminal","json","markdown"]), default="terminal")
@click.option("--internet-facing/--no-internet-facing", default=None)
@click.option("--environment", type=click.Choice(["prod","staging","dev"]), default=None)
@click.option("--sensitive-data/--no-sensitive-data", default=None)
@click.option("--no-color", is_flag=True, default=False)
@click.option("--api-key", envvar="ANTHROPIC_API_KEY")
def translate_finding(input_file, audience, verbose, score_only, output_format,
                      internet_facing, environment, sensitive_data, no_color, api_key):
    """Translate a security finding FILE for one or more audiences."""
    AudienceMode, ParserFactory, RiskContext, prioritize_findings, score_finding, TranslationEngine, OutputFormatter = _get_modules()
    formatter = OutputFormatter(no_color=no_color)
    try:
        if input_file == "-":
            raw_text = sys.stdin.read()
            try:
                raw_data = json.loads(raw_text)
            except json.JSONDecodeError:
                raw_data = raw_text
            parser = ParserFactory.for_data(raw_data)
            findings = parser.parse(raw_data)
        else:
            findings = ParserFactory.from_file(Path(input_file))
    except FileNotFoundError:
        formatter.print_error(f"File not found: {input_file}")
        sys.exit(1)
    except Exception as e:
        formatter.print_error(f"Failed to load input: {e}")
        sys.exit(1)
    if not findings:
        formatter.print_error("No findings found in input.")
        sys.exit(1)
    formatter.print_info(f"Loaded {len(findings)} finding(s)")
    ctx = RiskContext(internet_facing=internet_facing, environment=environment, contains_sensitive_data=sensitive_data)
    scored = prioritize_findings(findings, ctx)
    formatter.print_info(f"Risk scoring complete.")
    if output_format == "json":
        output = [{"finding": f.to_dict(), "risk_score": r.composite_score,
                   "risk_label": r.risk_label, "epss": r.epss_score,
                   "in_kev": r.in_kev, "scoring_method": r.scoring_method}
                  for f, r in scored]
        print(json.dumps(output, indent=2, default=str))
        return
    if score_only:
        for finding, risk_result in scored:
            formatter.print_finding_header(finding)
            formatter.print_risk_score(risk_result)
        return
    if not api_key and not os.getenv("ANTHROPIC_API_KEY"):
        formatter.print_error("No API key found. Set ANTHROPIC_API_KEY environment variable.")
        sys.exit(1)
    try:
        engine = TranslationEngine(api_key=api_key)
    except Exception as e:
        formatter.print_error(str(e))
        sys.exit(1)
    audience_modes = [AudienceMode(a) for a in audience]
    for finding, risk_result in scored:
        formatter.print_finding_header(finding)
        formatter.print_risk_score(risk_result)
        for mode in audience_modes:
            formatter.print_info(f"Generating {mode.value} translation...")
            translation = engine.translate(finding, mode, risk_score=risk_result.composite_score)
            formatter.print_translation(translation, mode, verbose=verbose)

@cli.command("demo")
@click.option("--audience", "-a", type=click.Choice(AUDIENCE_CHOICES), default="executive")
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--api-key", envvar="ANTHROPIC_API_KEY")
@click.option("--no-color", is_flag=True, default=False)
def demo(audience, verbose, api_key, no_color):
    """Run a demo translation using a built-in GuardDuty example finding."""
    AudienceMode, ParserFactory, RiskContext, prioritize_findings, score_finding, TranslationEngine, OutputFormatter = _get_modules()
    formatter = OutputFormatter(no_color=no_color)
    formatter.print_info("Loading demo GuardDuty finding...")
    demo_finding = {
        "id": "demo-abc123def456",
        "accountId": "123456789012",
        "region": "us-east-1",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "title": "EC2 instance i-0abc123def456 is performing SSH brute force attacks",
        "description": "EC2 instance i-0abc123def456 is performing SSH brute force attacks against external host 203.0.113.42.",
        "severity": 8.0,
        "service": {
            "action": {"actionType": "NETWORK_CONNECTION"},
            "eventFirstSeen": "2024-01-15T10:00:00Z",
            "eventLastSeen": "2024-01-15T10:45:00Z",
            "count": 1847,
        },
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-0abc123def456",
                "instanceType": "t3.medium",
                "tags": [
                    {"key": "Name", "value": "prod-web-01"},
                    {"key": "Environment", "value": "production"},
                ],
                "networkInterfaces": [{"publicIp": "54.12.34.56"}],
            },
        },
    }
    parser = ParserFactory.for_data(demo_finding)
    findings = parser.parse(demo_finding)
    ctx = RiskContext(internet_facing=True, environment="prod", contains_sensitive_data=True)
    scored = prioritize_findings(findings, ctx)
    finding, risk_result = scored[0]
    formatter.print_finding_header(finding)
    formatter.print_risk_score(risk_result)
    if not api_key and not os.getenv("ANTHROPIC_API_KEY"):
        formatter.print_info("\nNo API key set — showing risk score only.\nSet ANTHROPIC_API_KEY to enable AI translation.")
        return
    formatter.print_info(f"Generating {audience} translation...")
    engine = TranslationEngine(api_key=api_key)
    mode = AudienceMode(audience)
    translation = engine.translate(finding, mode, risk_score=risk_result.composite_score)
    formatter.print_translation(translation, mode, verbose=verbose)

def main():
    cli()

if __name__ == "__main__":
    main()
