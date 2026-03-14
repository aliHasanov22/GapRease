from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ============================================================
# CISO GAP MVP
# Single-file FastAPI prototype for hackathon demos.
# - Intake form -> current_state.md
# - Planner -> routes IAM + Network agents
# - Two domain agents run and produce findings markdown
# - Compliance agent deduplicates + maps to ISO 27001
# - Reporter produces executive summary markdown
# - Collaborative board API for status/assignee updates
# ============================================================

BASE_DIR = Path(os.getenv("SESSION_DATA_DIR", "./session_data"))
BASE_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="CISO GAP MVP", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Data models
# -----------------------------
Severity = Literal["Low", "Medium", "High", "Critical"]
Status = Literal["Open", "In Review", "In Progress", "Mitigated", "Accepted Risk"]


class IntakeRequest(BaseModel):
    org_name: str = Field(..., min_length=2)
    industry: str
    org_size_bucket: Literal["1-50", "51-500", "501-5000", "5000+"]
    framework: Literal["ISO 27001"] = "ISO 27001"
    cloud_providers: List[str] = Field(default_factory=list)
    existing_tools: List[str] = Field(default_factory=list)

    mfa_enabled: bool
    privileged_access_reviews: Literal["Never", "Ad Hoc", "Quarterly", "Monthly"]
    joiner_mover_leaver_process: bool
    sso_enabled: bool

    vpn_in_use: bool
    network_segmentation: Literal["None", "Basic", "Partial", "Strong"]
    firewall_rule_review: Literal["Never", "Ad Hoc", "Quarterly", "Monthly"]
    centralized_logging: bool

    edr_present: bool = False
    backups_tested: bool = False
    security_policies_documented: bool = False


class GapUpdateRequest(BaseModel):
    status: Optional[Status] = None
    assignee: Optional[str] = None


@dataclass
class Finding:
    domain: str
    title: str
    root_cause: str
    severity: Severity
    confidence: float
    evidence: List[str]
    recommendation: str
    control_family: str
    disputed: bool = False
    conflicting_note: Optional[str] = None


@dataclass
class Gap:
    gap_id: str
    title: str
    domain: str
    root_cause: str
    severity: Severity
    confidence: float
    evidence: List[str]
    recommendation: str
    framework_mappings: List[Dict[str, str]]
    status: Status = "Open"
    assignee: Optional[str] = None
    created_at: str = field(default_factory=lambda: now_iso())
    updated_at: str = field(default_factory=lambda: now_iso())


# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_session_dirs(session_id: str) -> Path:
    session_dir = BASE_DIR / f"session_{session_id}"
    (session_dir / "findings").mkdir(parents=True, exist_ok=True)
    return session_dir


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def severity_weight(severity: Severity) -> int:
    return {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }[severity]


def evidence_strength(evidence: List[str]) -> float:
    count = len([e for e in evidence if e.strip()])
    if count >= 3:
        return 1.0
    if count == 2:
        return 0.8
    return 0.6


def priority_score(severity: Severity, confidence: float, evidence: List[str]) -> float:
    return round(severity_weight(severity) * confidence * evidence_strength(evidence), 2)


def canonical_gap_id(domain: str, control_family: str, root_cause: str) -> str:
    raw = f"{domain}|{control_family}|{root_cause}".lower().strip()
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
    return f"{domain.lower().replace(' ', '-')}-{control_family.lower().replace(' ', '-')}-{digest}"


def markdown_heading(title: str, level: int = 1) -> str:
    return f"{'#' * level} {title}\n"


def finding_to_markdown(f: Finding) -> str:
    evidence_md = "\n".join([f"- {item}" for item in f.evidence])
    disputed_md = f"\n- Conflict Note: {f.conflicting_note}" if f.disputed and f.conflicting_note else ""
    return (
        f"## {f.title}\n"
        f"- Domain: {f.domain}\n"
        f"- Severity: {f.severity}\n"
        f"- Confidence: {f.confidence:.2f}\n"
        f"- Control Family: {f.control_family}\n"
        f"- Root Cause: {f.root_cause}\n"
        f"- Recommendation: {f.recommendation}\n"
        f"- Disputed: {'Yes' if f.disputed else 'No'}{disputed_md}\n\n"
        f"### Evidence\n{evidence_md}\n\n"
    )


def gap_to_markdown(g: Gap) -> str:
    mappings = "\n".join(
        [f"- {m['framework']}: {m['control']}" for m in g.framework_mappings]
    )
    evidence_md = "\n".join([f"- {item}" for item in g.evidence])
    return (
        f"## {g.title}\n"
        f"- Gap ID: {g.gap_id}\n"
        f"- Domain: {g.domain}\n"
        f"- Severity: {g.severity}\n"
        f"- Confidence: {g.confidence:.2f}\n"
        f"- Status: {g.status}\n"
        f"- Assignee: {g.assignee or 'Unassigned'}\n"
        f"- Root Cause: {g.root_cause}\n"
        f"- Recommendation: {g.recommendation}\n"
        f"- Updated At: {g.updated_at}\n\n"
        f"### Evidence\n{evidence_md}\n\n"
        f"### Framework Mappings\n{mappings}\n\n"
    )


# -----------------------------
# Agent layer
# -----------------------------
def planner(intake: IntakeRequest) -> Dict[str, Any]:
    agents = ["iam", "network"]
    dependencies = {"iam": [], "network": [], "compliance": ["iam", "network"], "reporter": ["compliance"]}
    return {
        "selected_agents": agents,
        "execution_mode": "parallel",
        "dependencies": dependencies,
        "reasoning": [
            "IAM and Network are sufficient for MVP current-state analysis.",
            "Compliance mapping depends on normalized findings from both agents.",
            "Reporter depends on the consolidated gap registry.",
        ],
    }


def iam_agent(intake: IntakeRequest) -> List[Finding]:
    findings: List[Finding] = []

    if not intake.mfa_enabled:
        findings.append(
            Finding(
                domain="IAM",
                title="MFA is not enabled across the organization",
                root_cause="Missing strong authentication baseline",
                severity="Critical",
                confidence=0.95,
                evidence=[
                    "Intake indicates MFA is disabled.",
                    "Authentication baseline is not enforced for all users.",
                    "Elevated takeover risk exists for user and admin accounts.",
                ],
                recommendation="Enforce MFA for workforce identities, admin accounts, VPN, and SaaS login flows.",
                control_family="Authentication",
            )
        )

    if intake.privileged_access_reviews in {"Never", "Ad Hoc"}:
        findings.append(
            Finding(
                domain="IAM",
                title="Privileged access reviews are not formalized",
                root_cause="Missing periodic privileged access review control",
                severity="High",
                confidence=0.88,
                evidence=[
                    f"Declared access review frequency: {intake.privileged_access_reviews}.",
                    "No structured recurring review cadence is present.",
                ],
                recommendation="Implement monthly or quarterly privileged access reviews with named owners and evidence retention.",
                control_family="Privileged Access",
            )
        )

    if not intake.joiner_mover_leaver_process:
        findings.append(
            Finding(
                domain="IAM",
                title="Identity lifecycle process is incomplete",
                root_cause="Missing joiner-mover-leaver workflow",
                severity="High",
                confidence=0.86,
                evidence=[
                    "Joiner/mover/leaver process is not documented in intake.",
                    "Stale access and delayed deprovisioning risk exists.",
                ],
                recommendation="Define identity lifecycle workflows tied to HR or manager approval events.",
                control_family="Identity Lifecycle",
            )
        )

    if not intake.sso_enabled:
        findings.append(
            Finding(
                domain="IAM",
                title="SSO is not enabled for central identity control",
                root_cause="Fragmented authentication management",
                severity="Medium",
                confidence=0.76,
                evidence=[
                    "SSO is disabled according to intake.",
                    "Authentication policies may be inconsistent across apps.",
                ],
                recommendation="Adopt SSO for critical SaaS and internal systems to centralize policy enforcement.",
                control_family="Federation",
            )
        )

    return findings


def network_agent(intake: IntakeRequest) -> List[Finding]:
    findings: List[Finding] = []

    if intake.network_segmentation in {"None", "Basic"}:
        findings.append(
            Finding(
                domain="Network Security",
                title="Network segmentation is insufficient",
                root_cause="Flat or weakly segmented network design",
                severity="High",
                confidence=0.91,
                evidence=[
                    f"Segmentation maturity selected: {intake.network_segmentation}.",
                    "Lateral movement resistance is likely limited.",
                    "Security zones are not strongly enforced.",
                ],
                recommendation="Introduce role-based segmentation for users, servers, management plane, and critical services.",
                control_family="Segmentation",
            )
        )

    if intake.firewall_rule_review in {"Never", "Ad Hoc"}:
        findings.append(
            Finding(
                domain="Network Security",
                title="Firewall rule reviews are inconsistent",
                root_cause="Missing recurring firewall governance",
                severity="Medium",
                confidence=0.82,
                evidence=[
                    f"Declared firewall review cadence: {intake.firewall_rule_review}.",
                    "Unused, overly broad, or stale rules may persist.",
                ],
                recommendation="Review firewall rules monthly or quarterly with owner validation and change logs.",
                control_family="Firewall Governance",
            )
        )

    if intake.vpn_in_use and not intake.mfa_enabled:
        findings.append(
            Finding(
                domain="Network Security",
                title="Remote access is exposed because VPN lacks MFA backing",
                root_cause="Remote access control not hardened",
                severity="Critical",
                confidence=0.92,
                evidence=[
                    "VPN is in use.",
                    "MFA is disabled.",
                    "Credential compromise would materially increase remote access risk.",
                ],
                recommendation="Require MFA on all remote access paths and review VPN group membership.",
                control_family="Remote Access",
            )
        )

    if not intake.centralized_logging:
        findings.append(
            Finding(
                domain="Network Security",
                title="Centralized logging is missing",
                root_cause="Insufficient monitoring and event visibility",
                severity="High",
                confidence=0.89,
                evidence=[
                    "Centralized logging is not enabled.",
                    "Detection and incident reconstruction capabilities are reduced.",
                ],
                recommendation="Forward security-relevant logs to a central SIEM or logging platform with retention standards.",
                control_family="Monitoring",
            )
        )

    return findings


def detect_disputes(findings: List[Finding]) -> List[Finding]:
    # Simple MVP rule: if a finding has lower confidence and overlaps another domain statement
    # about remote access/authentication, mark it as disputed for human review.
    disputed: List[Finding] = []
    titles = [f.title.lower() for f in findings]
    remote = any("remote access" in t or "vpn" in t for t in titles)
    mfa = any("mfa" in t for t in titles)
    if remote and mfa:
        for f in findings:
            if f.control_family in {"Authentication", "Remote Access"} and f.confidence < 0.94:
                f.disputed = True
                f.conflicting_note = "Overlapping IAM and Network perspectives detected on remote authentication risk. Human validation recommended."
                disputed.append(f)
    return disputed


def map_to_iso27001(finding: Finding) -> List[Dict[str, str]]:
    mapping_table = {
        "Authentication": [{"framework": "ISO 27001", "control": "Access control and authentication policy"}],
        "Privileged Access": [{"framework": "ISO 27001", "control": "Privileged access restriction and review"}],
        "Identity Lifecycle": [{"framework": "ISO 27001", "control": "User lifecycle and access provisioning"}],
        "Federation": [{"framework": "ISO 27001", "control": "Central identity and secure access management"}],
        "Segmentation": [{"framework": "ISO 27001", "control": "Network security and segregation"}],
        "Firewall Governance": [{"framework": "ISO 27001", "control": "Network controls and change governance"}],
        "Remote Access": [{"framework": "ISO 27001", "control": "Secure remote access controls"}],
        "Monitoring": [{"framework": "ISO 27001", "control": "Logging, monitoring, and event analysis"}],
    }
    return mapping_table.get(
        finding.control_family,
        [{"framework": "ISO 27001", "control": "General control mapping"}],
    )


def compliance_agent(findings: List[Finding]) -> Dict[str, List[Gap]]:
    gap_map: Dict[str, Gap] = {}
    disputed_items: List[Gap] = []

    detect_disputes(findings)

    for f in findings:
        gap_id = canonical_gap_id(f.domain, f.control_family, f.root_cause)
        mappings = map_to_iso27001(f)

        if gap_id in gap_map:
            existing = gap_map[gap_id]
            existing.evidence = sorted(list(set(existing.evidence + f.evidence)))
            existing.confidence = max(existing.confidence, f.confidence)
            existing.updated_at = now_iso()
            if severity_weight(f.severity) > severity_weight(existing.severity):
                existing.severity = f.severity
        else:
            gap_map[gap_id] = Gap(
                gap_id=gap_id,
                title=f.title,
                domain=f.domain,
                root_cause=f.root_cause,
                severity=f.severity,
                confidence=f.confidence,
                evidence=f.evidence,
                recommendation=f.recommendation,
                framework_mappings=mappings,
            )

        if f.disputed:
            disputed_items.append(gap_map[gap_id])

    gaps = list(gap_map.values())
    gaps.sort(key=lambda g: priority_score(g.severity, g.confidence, g.evidence), reverse=True)
    return {"gaps": gaps, "disputed": disputed_items}


def coverage_estimate(gaps: List[Gap]) -> Dict[str, Any]:
    # Simple demo scoring: baseline 85 minus weighted penalties.
    score = 85.0
    for g in gaps:
        if g.severity == "Critical":
            score -= 10
        elif g.severity == "High":
            score -= 6
        elif g.severity == "Medium":
            score -= 3
        else:
            score -= 1
    score = max(15.0, round(score, 1))

    if score >= 80:
        maturity = "Strong"
    elif score >= 65:
        maturity = "Moderate"
    elif score >= 45:
        maturity = "Needs Improvement"
    else:
        maturity = "Weak"

    return {
        "framework": "ISO 27001",
        "coverage_percent": score,
        "maturity": maturity,
        "industry_average": 71.0,
        "peer_bucket": "Tech / 51-500",
    }


def reporter(intake: IntakeRequest, gaps: List[Gap], disputed: List[Gap], coverage: Dict[str, Any]) -> str:
    top = gaps[:5]
    top_md = "\n".join(
        [
            f"- **{g.title}** ({g.domain}) — {g.severity}, confidence {g.confidence:.2f}, priority {priority_score(g.severity, g.confidence, g.evidence)}"
            for g in top
        ]
    ) or "- No major gaps identified."

    disputed_md = "\n".join([f"- {g.title} ({g.gap_id})" for g in disputed]) or "- No disputed findings."

    return (
        f"# Executive Summary\n\n"
        f"**Organization:** {intake.org_name}  \n"
        f"**Industry:** {intake.industry}  \n"
        f"**Size Bucket:** {intake.org_size_bucket}  \n"
        f"**Framework:** {intake.framework}  \n"
        f"**Generated At:** {now_iso()}\n\n"
        f"## Summary\n"
        f"This MVP assessment analyzed IAM and Network Security controls based on structured current-state intake data. "
        f"Findings were normalized into a deduplicated GAP register and mapped to ISO 27001 control areas. "
        f"The estimated coverage score is **{coverage['coverage_percent']}%**, compared with an industry demo average of **{coverage['industry_average']}%**.\n\n"
        f"## Top Risks\n{top_md}\n\n"
        f"## Disputed Findings\n{disputed_md}\n\n"
        f"## Recommended Next Steps\n"
        f"- Close critical identity and remote access gaps first.\n"
        f"- Establish recurring governance for access review and firewall review.\n"
        f"- Improve centralized monitoring and evidence retention.\n"
        f"- Assign owners in the GAP board and track mitigation status.\n"
    )


# -----------------------------
# Persistence / rendering
# -----------------------------
def save_session_artifacts(
    session_id: str,
    intake: IntakeRequest,
    plan: Dict[str, Any],
    iam_findings: List[Finding],
    network_findings: List[Finding],
    gaps: List[Gap],
    disputed: List[Gap],
    coverage: Dict[str, Any],
    report_md: str,
) -> None:
    session_dir = ensure_session_dirs(session_id)

    write_json(session_dir / "context.json", intake.model_dump())
    write_json(session_dir / "planner.json", plan)
    write_json(session_dir / "board.json", [asdict(g) for g in gaps])
    write_json(session_dir / "benchmark.json", coverage)

    current_state_md = (
        markdown_heading("Current State")
        + "\n".join([f"- **{k}**: {v}" for k, v in intake.model_dump().items()])
        + "\n"
    )
    write_text(session_dir / "current_state.md", current_state_md)

    iam_md = markdown_heading("IAM Findings") + "\n".join([finding_to_markdown(f) for f in iam_findings])
    network_md = markdown_heading("Network Security Findings") + "\n".join([finding_to_markdown(f) for f in network_findings])
    gaps_md = markdown_heading("GAP Register") + "\n".join([gap_to_markdown(g) for g in gaps])
    disputed_md = markdown_heading("Disputed Findings") + "\n".join([gap_to_markdown(g) for g in disputed])

    write_text(session_dir / "findings" / "iam.md", iam_md)
    write_text(session_dir / "findings" / "network.md", network_md)
    write_text(session_dir / "gaps.md", gaps_md)
    write_text(session_dir / "disputed.md", disputed_md)
    write_text(session_dir / "report_draft.md", report_md)


def load_board(session_id: str) -> List[Dict[str, Any]]:
    session_dir = ensure_session_dirs(session_id)
    return read_json(session_dir / "board.json", default=[])


def save_board(session_id: str, board: List[Dict[str, Any]]) -> None:
    session_dir = ensure_session_dirs(session_id)
    write_json(session_dir / "board.json", board)


# -----------------------------
# API endpoints
# -----------------------------
@app.get("/")
def root() -> Dict[str, str]:
    return {"message": "CISO GAP MVP is running"}


@app.post("/api/sessions")
def create_session(intake: IntakeRequest) -> Dict[str, Any]:
    session_id = str(uuid4())
    plan = planner(intake)

    iam_findings = iam_agent(intake)
    network_findings = network_agent(intake)
    all_findings = iam_findings + network_findings

    compliance = compliance_agent(all_findings)
    gaps: List[Gap] = compliance["gaps"]
    disputed: List[Gap] = compliance["disputed"]
    coverage = coverage_estimate(gaps)
    report_md = reporter(intake, gaps, disputed, coverage)

    save_session_artifacts(
        session_id=session_id,
        intake=intake,
        plan=plan,
        iam_findings=iam_findings,
        network_findings=network_findings,
        gaps=gaps,
        disputed=disputed,
        coverage=coverage,
        report_md=report_md,
    )

    return {
        "session_id": session_id,
        "plan": plan,
        "summary": {
            "total_findings": len(all_findings),
            "total_gaps": len(gaps),
            "disputed_count": len(disputed),
            "coverage": coverage,
        },
    }


@app.get("/api/sessions/{session_id}")
def get_session_summary(session_id: str) -> Dict[str, Any]:
    session_dir = ensure_session_dirs(session_id)
    context = read_json(session_dir / "context.json", default=None)
    planner_json = read_json(session_dir / "planner.json", default=None)
    board = read_json(session_dir / "board.json", default=[])
    benchmark = read_json(session_dir / "benchmark.json", default={})

    if context is None:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id": session_id,
        "context": context,
        "planner": planner_json,
        "board_count": len(board),
        "benchmark": benchmark,
        "artifacts": {
            "current_state_md": str(session_dir / "current_state.md"),
            "iam_md": str(session_dir / "findings" / "iam.md"),
            "network_md": str(session_dir / "findings" / "network.md"),
            "gaps_md": str(session_dir / "gaps.md"),
            "disputed_md": str(session_dir / "disputed.md"),
            "report_draft_md": str(session_dir / "report_draft.md"),
        },
    }


@app.get("/api/sessions/{session_id}/board")
def get_gap_board(session_id: str) -> Dict[str, Any]:
    board = load_board(session_id)
    if not board:
        session_dir = ensure_session_dirs(session_id)
        if not (session_dir / "context.json").exists():
            raise HTTPException(status_code=404, detail="Session not found")
    return {"items": board}


@app.patch("/api/sessions/{session_id}/board/{gap_id}")
def update_gap(session_id: str, gap_id: str, payload: GapUpdateRequest) -> Dict[str, Any]:
    board = load_board(session_id)
    for item in board:
        if item["gap_id"] == gap_id:
            if payload.status is not None:
                item["status"] = payload.status
            if payload.assignee is not None:
                item["assignee"] = payload.assignee
            item["updated_at"] = now_iso()
            save_board(session_id, board)
            return {"updated": item}

    raise HTTPException(status_code=404, detail="Gap not found")


@app.get("/api/sessions/{session_id}/report")
def get_report(session_id: str) -> Dict[str, str]:
    session_dir = ensure_session_dirs(session_id)
    report_path = session_dir / "report_draft.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return {"markdown": report_path.read_text(encoding="utf-8")}


@app.get("/api/sessions/{session_id}/benchmark")
def get_benchmark(session_id: str) -> Dict[str, Any]:
    session_dir = ensure_session_dirs(session_id)
    benchmark = read_json(session_dir / "benchmark.json", default=None)
    if benchmark is None:
        raise HTTPException(status_code=404, detail="Benchmark not found")
    return benchmark


# -----------------------------
# Local development notes
# -----------------------------
# Run:
#   pip install fastapi uvicorn pydantic
#   uvicorn ciso_gap_mvp_app:app --reload
#
# Example POST /api/sessions body:
# {
#   "org_name": "Acme Fintech",
#   "industry": "Tech",
#   "org_size_bucket": "51-500",
#   "framework": "ISO 27001",
#   "cloud_providers": ["AWS"],
#   "existing_tools": ["Microsoft 365", "Defender"],
#   "mfa_enabled": false,
#   "privileged_access_reviews": "Never",
#   "joiner_mover_leaver_process": false,
#   "sso_enabled": false,
#   "vpn_in_use": true,
#   "network_segmentation": "Basic",
#   "firewall_rule_review": "Ad Hoc",
#   "centralized_logging": false,
#   "edr_present": true,
#   "backups_tested": false,
#   "security_policies_documented": false
# }
