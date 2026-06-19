from __future__ import annotations
import logging
import urllib.request
import urllib.error
import json
import os
from dataclasses import dataclass, field
from typing import Optional
from ..models.finding import NormalizedFinding, Severity

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_epss_cache: dict[str, float] = {}
_kev_cache: set[str] = set()
_kev_loaded: bool = False


def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    uncached = [c for c in cve_ids if c not in _epss_cache]
    if uncached:
        try:
            cve_param = ",".join(uncached)
            url = f"{EPSS_API}?cve={cve_param}"
            req = urllib.request.Request(url, headers={"User-Agent": "SFT/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            for item in data.get("data", []):
                cve = item.get("cve", "")
                epss = float(item.get("epss", 0))
                _epss_cache[cve] = epss
        except Exception as e:
            logger.warning(f"EPSS API unavailable: {e}")
    return {c: _epss_cache.get(c, 0.0) for c in cve_ids}


def _load_kev() -> set[str]:
    global _kev_loaded, _kev_cache
    if _kev_loaded:
        return _kev_cache
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "SFT/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
        _kev_loaded = True
        logger.info(f"KEV catalog loaded: {len(_kev_cache)} entries")
    except Exception as e:
        logger.warning(f"KEV catalog unavailable: {e}")
        _kev_loaded = True
    return _kev_cache


def is_in_kev(cve_ids: list[str]) -> bool:
    if not cve_ids:
        return False
    kev = _load_kev()
    return any(c in kev for c in cve_ids)


@dataclass
class RiskContext:
    internet_facing: Optional[bool] = None
    environment: Optional[str] = None
    contains_sensitive_data: Optional[bool] = None
    exploit_available: Optional[bool] = None
    asset_criticality: Optional[str] = None


@dataclass
class RiskScoreResult:
    composite_score: float
    base_score: float
    epss_score: float
    epss_percentile: float
    in_kev: bool
    exposure_bonus: float
    data_bonus: float
    env_multiplier: float
    risk_label: str
    risk_rationale: str
    scoring_method: str


def _env_multiplier(environment: Optional[str]) -> float:
    if not environment:
        return 0.6
    env = environment.lower()
    if env in ("prod", "production", "live"): return 1.0
    if env in ("staging", "stage", "uat"): return 0.7
    if env in ("dev", "development", "local", "test"): return 0.3
    return 0.6


def _severity_to_base(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5, Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0, Severity.LOW: 2.5,
        Severity.INFORMATIONAL: 0.5, Severity.UNKNOWN: 0.0,
    }[severity]


def _risk_label(score: float) -> str:
    if score >= 8.5: return "Critical"
    if score >= 6.5: return "High"
    if score >= 4.0: return "Medium"
    if score >= 1.0: return "Low"
    return "Informational"


def score_finding(
    finding: NormalizedFinding,
    context: Optional[RiskContext] = None,
    fetch_live_data: bool = True,
) -> RiskScoreResult:
    ctx = context or RiskContext()

    # ── Step 1: Get EPSS score if CVE IDs exist ──────────────────────────────
    epss_score = 0.0
    epss_percentile = 0.0
    scoring_method = "severity"

    if finding.cve_ids and fetch_live_data:
        epss_scores = _fetch_epss(finding.cve_ids)
        if epss_scores:
            epss_score = max(epss_scores.values())
            epss_percentile = round(epss_score * 100, 1)
            scoring_method = "epss"

    # ── Step 2: Check CISA KEV ────────────────────────────────────────────────
    in_kev = False
    if finding.cve_ids and fetch_live_data:
        in_kev = is_in_kev(finding.cve_ids)

    # ── Step 3: Calculate base score ─────────────────────────────────────────
    # Priority: KEV > EPSS > CVSS > Severity
    if in_kev:
        # KEV means actively exploited — floor the base at 8.0
        base_score = max(8.0, finding.cvss.base_score if finding.cvss else 8.0)
        scoring_method = "kev"
    elif epss_score > 0:
        # Convert EPSS probability to 0-10 scale
        # EPSS 50%+ = very high likelihood, treat as at least 7.0
        epss_as_score = epss_score * 10
        cvss_base = finding.cvss.base_score if finding.cvss else _severity_to_base(finding.severity)
        # Weighted blend: 60% EPSS likelihood + 40% CVSS impact
        base_score = (epss_as_score * 0.60) + (cvss_base * 0.40)
        scoring_method = "epss+cvss"
    elif finding.cvss:
        base_score = finding.cvss.base_score
        scoring_method = "cvss"
    else:
        base_score = _severity_to_base(finding.severity)
        scoring_method = "severity"

    base_score = max(0.0, min(10.0, base_score))

    # ── Step 4: Context bonuses ───────────────────────────────────────────────
    is_internet_facing = ctx.internet_facing
    if is_internet_facing is None and finding.affected_asset:
        is_internet_facing = finding.affected_asset.internet_facing
    exposure_bonus = 1.5 if is_internet_facing else 0.0

    has_sensitive_data = ctx.contains_sensitive_data
    if has_sensitive_data is None and finding.affected_asset:
        has_sensitive_data = finding.affected_asset.contains_sensitive_data
    data_bonus = 1.0 if has_sensitive_data else 0.0

    env = ctx.environment
    if env is None and finding.affected_asset:
        env = finding.affected_asset.environment
    env_mult = _env_multiplier(env)

    # ── Step 5: Composite score ───────────────────────────────────────────────
    raw = base_score + exposure_bonus + data_bonus
    env_adjusted = raw * env_mult

    # KEV is a hard floor — actively exploited vulnerabilities stay urgent
    # regardless of environment context. We genuinely do not know if "no
    # environment data" means dev or prod, so we err toward caution.
    if in_kev:
        composite = max(env_adjusted, 8.0)
    elif epss_score >= 0.5:
        # Very high exploitation probability also gets a floor, just lower
        composite = max(env_adjusted, 6.5)
    else:
        composite = env_adjusted

    composite = min(10.0, composite)
    composite = round(composite, 2)

    # ── Step 6: Build rationale ───────────────────────────────────────────────
    rationale_parts = []

    if in_kev:
        rationale_parts.append("IN CISA KEV — actively exploited in the wild")
    if epss_score > 0:
        rationale_parts.append(f"EPSS: {epss_percentile}% probability of exploitation in 30 days")
    if finding.cvss:
        rationale_parts.append(f"CVSS: {finding.cvss.base_score}")
    if is_internet_facing:
        rationale_parts.append("internet-facing asset")
    if has_sensitive_data:
        rationale_parts.append("handles sensitive data")
    if env:
        rationale_parts.append(f"environment: {env}")

    rationale = f"[{scoring_method.upper()}] Base {base_score:.1f}/10. " + (
        " | ".join(rationale_parts) if rationale_parts
        else "No additional risk context available."
    )

    return RiskScoreResult(
        composite_score=composite,
        base_score=base_score,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        in_kev=in_kev,
        exposure_bonus=exposure_bonus,
        data_bonus=data_bonus,
        env_multiplier=env_mult,
        risk_label=_risk_label(composite),
        risk_rationale=rationale,
        scoring_method=scoring_method,
    )


def prioritize_findings(
    findings: list[NormalizedFinding],
    context: Optional[RiskContext] = None,
    fetch_live_data: bool = True,
) -> list[tuple[NormalizedFinding, RiskScoreResult]]:
    scored = []
    for finding in findings:
        try:
            result = score_finding(finding, context, fetch_live_data=fetch_live_data)
            finding.risk_score = result.composite_score
            finding.exploit_available = result.in_kev or result.epss_score > 0.3
            scored.append((finding, result))
        except Exception as e:
            logger.error(f"Risk scoring failed for {finding.id}: {e}")
    scored.sort(key=lambda x: x[1].composite_score, reverse=True)
    return scored
