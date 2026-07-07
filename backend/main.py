"""
AuthMap Backend — FastAPI application.
Exposes scan orchestration, graph analysis, and compliance endpoints.
"""

import os
import sys
import io
import csv
import json
import logging
from typing import Optional, List
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx
import jwt

# Add collectors to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))

from collectors.scan_orchestrator import ScanOrchestrator
from collectors.breach_cost_estimator import Region

load_dotenv()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Clerk JWT Auth
# ---------------------------------------------------------------------------

_cached_jwks: Optional[dict] = None


async def _get_clerk_jwks() -> dict:
    """Fetch and cache Clerk's JWKS key set."""
    global _cached_jwks
    if _cached_jwks is not None:
        return _cached_jwks

    issuer = os.getenv("CLERK_JWT_ISSUER", "").rstrip("/")
    if not issuer:
        raise HTTPException(status_code=500, detail="CLERK_JWT_ISSUER not configured")

    jwks_url = f"{issuer}/.well-known/jwks.json"
    async with httpx.AsyncClient() as client:
        resp = await client.get(jwks_url, timeout=10)
        resp.raise_for_status()
        _cached_jwks = resp.json()

    return _cached_jwks


async def get_clerk_user_id(request: Request) -> str:
    """FastAPI dependency — validate Clerk JWT and return the user's clerk_id (sub)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header.removeprefix("Bearer ").strip()
    issuer = os.getenv("CLERK_JWT_ISSUER", "").rstrip("/")

    try:
        jwks = await _get_clerk_jwks()
        # Build signing keys from JWKS
        public_keys: dict[str, jwt.algorithms.RSAAlgorithm] = {}
        for jwk_key in jwks.get("keys", []):
            kid = jwk_key.get("kid")
            if kid:
                public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_key)

        # Decode header to find the kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if kid not in public_keys:
            raise HTTPException(status_code=401, detail="JWT kid not found in JWKS")

        payload = jwt.decode(
            token,
            key=public_keys[kid],
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False},
        )
        clerk_id = payload.get("sub")
        if not clerk_id:
            raise HTTPException(status_code=401, detail="JWT missing sub claim")
        return clerk_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Clerk JWT verification failed")
        raise HTTPException(status_code=401, detail=f"Authentication failed: {e}")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    provider: str  # 'aws' or 'gcp'
    # AWS fields
    aws_access_key_id: Optional[str] = None
    aws_secret_key: Optional[str] = None
    region: Optional[str] = 'us-east-1'
    # GCP fields
    gcp_project_id: Optional[str] = None
    gcp_service_account_key: Optional[str] = None
    # Scan options
    scan_depth: Optional[str] = 'standard'
    selected_compliances: Optional[List[str]] = ['SOC2', 'DPDP']
    # Risk scoring inputs
    cost_region: Optional[str] = 'INDIA'  # For breach cost estimation
    annual_revenue: Optional[float] = None
    # Neo4j Aura (optional — overrides env defaults)
    neo4j_uri: Optional[str] = None
    neo4j_username: Optional[str] = None
    neo4j_password: Optional[str] = None
    neo4j_project_id: Optional[str] = None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AuthMap API",
    description="IAM security scanner, graph-based attack-path analysis & breach-cost estimation.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

scan_status: dict[str, dict] = {}


def get_orchestrator(neo4j_uri=None, neo4j_user=None, neo4j_password=None) -> ScanOrchestrator:
    """Instantiate a ScanOrchestrator with env-var defaults (overridable)."""
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    n_uri = neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
    n_user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
    n_pass = neo4j_password or os.getenv("NEO4J_PASSWORD", "password")
    return ScanOrchestrator(supabase_url, supabase_key, n_uri, n_user, n_pass)


# ---------------------------------------------------------------------------
# Background scan pipeline
# ---------------------------------------------------------------------------

async def run_scan_pipeline(scan_id: str, clerk_id: str, req: ScanRequest):
    """Execute the full scan pipeline in the background."""
    try:
        scan_status[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "phase": "initializing",
            "progress": 0,
            "error": None,
        }

        orchestrator = get_orchestrator(
            neo4j_uri=req.neo4j_uri,
            neo4j_user=req.neo4j_username,
            neo4j_password=req.neo4j_password,
        )

        # Phase 1 — Discovery
        scan_status[scan_id].update(phase="discovery", progress=10)
        orchestrator.run_scan(
            scan_id=scan_id,
            clerk_id=clerk_id,
            aws_access_key=req.aws_access_key_id,
            aws_secret_key=req.aws_secret_key,
            aws_region=req.region,
            gcp_sa_json=req.gcp_service_account_key,
            gcp_project_id=req.gcp_project_id,
            selected_compliances=req.selected_compliances,
        )

        # Phase 2 — Graph analysis
        scan_status[scan_id].update(phase="graph_building", progress=40)
        paths = orchestrator.run_graph_analysis(scan_id)

        # Phase 3 — Attack paths & cost
        scan_status[scan_id].update(phase="risk_scoring", progress=60)
        orchestrator.create_attack_paths(
            scan_id,
            clerk_id,
            paths,
            req.selected_compliances,
            region_name=req.cost_region,
            annual_revenue=req.annual_revenue,
        )

        # Phase 4 — Compliance
        scan_status[scan_id].update(phase="compliance", progress=80)
        orchestrator.create_compliance_violations(scan_id, clerk_id, req.selected_compliances)

        # Phase 5 — Finalize
        scan_status[scan_id].update(phase="reporting", progress=90)
        orchestrator.finalize_scan(scan_id)

        scan_status[scan_id].update(status="completed", phase="done", progress=100)

    except Exception as exc:
        logger.exception("Scan pipeline failed for %s", scan_id)
        scan_status[scan_id] = {
            "scan_id": scan_id,
            "status": "failed",
            "phase": "error",
            "progress": scan_status.get(scan_id, {}).get("progress", 0),
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/scan/run")
async def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Kick off a scan pipeline in the background."""
    orchestrator = get_orchestrator(
        neo4j_uri=req.neo4j_uri,
        neo4j_user=req.neo4j_username,
        neo4j_password=req.neo4j_password,
    )

    scan_id = orchestrator.create_scan_record(
        clerk_id=clerk_id,
        credential_id=req.neo4j_project_id or "default",
        scan_name=f"{req.provider.upper()} Scan",
        scan_type=req.scan_depth,
        csp_target=req.provider,
        selected_compliances=req.selected_compliances,
    )

    background_tasks.add_task(run_scan_pipeline, scan_id, clerk_id, req)
    return {"scan_id": scan_id, "status": "started"}


@app.get("/scan/status/{scan_id}")
async def get_scan_status(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return current scan progress (in-memory first, then Supabase fallback)."""
    if scan_id in scan_status:
        return scan_status[scan_id]

    # Fallback to Supabase
    try:
        orchestrator = get_orchestrator()
        result = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute()
        if result.data:
            scan = result.data[0]
            return {
                "scan_id": scan_id,
                "status": scan.get("status", "unknown"),
                "phase": scan.get("current_phase", ""),
                "progress": scan.get("phase_progress", 0),
                "error": scan.get("error_message"),
            }
    except Exception as exc:
        logger.warning("Supabase lookup failed for scan %s: %s", scan_id, exc)

    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/scan/results/latest")
async def get_latest_scan(clerk_id: str = Depends(get_clerk_user_id)):
    """Return the most recent scan record for the authenticated user."""
    orchestrator = get_orchestrator()
    result = (
        orchestrator.supabase.table("iam_scans")
        .select("*")
        .eq("clerk_id", clerk_id)
        .order("started_at", desc=True)
        .limit(1)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="No scans found for this user")
    return result.data[0]


@app.get("/scan/results/{scan_id}")
async def get_scan_results(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return the full scan record."""
    orchestrator = get_orchestrator()
    result = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result.data[0]


@app.get("/scan/graph/{scan_id}")
async def get_scan_graph(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return Cytoscape.js-formatted graph elements."""
    orchestrator = get_orchestrator()
    return orchestrator.get_graph_for_cytoscape(scan_id)


@app.get("/scan/attack-paths/{scan_id}")
async def get_attack_paths(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return all attack paths for a scan."""
    orchestrator = get_orchestrator()
    result = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute()
    return result.data


@app.get("/scan/cost-analysis/{scan_id}")
async def get_cost_analysis(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return combined cost analysis data for a scan."""
    orchestrator = get_orchestrator()
    cost_result = orchestrator.supabase.table("cost_analyses").select("*").eq("scan_id", scan_id).execute()
    paths_result = orchestrator.supabase.table("attack_paths").select(
        "id,path_name,estimated_cost_impact,cost_breakdown,cost_score"
    ).eq("scan_id", scan_id).execute()

    return {
        "cost_analyses": cost_result.data,
        "path_costs": paths_result.data,
    }


@app.get("/scan/compliance/{scan_id}")
async def get_compliance_violations(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return compliance violations for a scan."""
    orchestrator = get_orchestrator()
    result = orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", scan_id).execute()
    return result.data


@app.get("/scan/findings/{scan_id}")
async def get_findings_summary(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return an aggregated findings summary for the scan."""
    orchestrator = get_orchestrator()

    # Entities
    entities_result = orchestrator.supabase.table("scan_entities").select("*").eq("scan_id", scan_id).execute()
    entities = entities_result.data or []
    by_type: dict[str, int] = {}
    admin_count = overprivileged_count = dormant_count = 0
    for e in entities:
        etype = e.get("entity_type", "unknown")
        by_type[etype] = by_type.get(etype, 0) + 1
        rf = e.get("static_risk_factors", {})
        if rf.get("is_admin"):
            admin_count += 1
        if rf.get("is_overprivileged"):
            overprivileged_count += 1
        if rf.get("is_dormant"):
            dormant_count += 1

    # Attack paths
    paths_result = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute()
    paths = paths_result.data or []
    path_scores = [p.get("hybrid_risk_score", 0) for p in paths]
    total_cost = sum(p.get("estimated_cost_impact", 0) for p in paths)

    # Violations
    violations_result = orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", scan_id).execute()
    violations = violations_result.data or []
    by_severity: dict[str, int] = {}
    for v in violations:
        sev = v.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "entities": {"total": len(entities), "by_type": by_type},
        "risk": {
            "admin_count": admin_count,
            "overprivileged_count": overprivileged_count,
            "dormant_count": dormant_count,
        },
        "attack_paths": {
            "total": len(paths),
            "max_score": max(path_scores, default=0),
            "avg_score": round(sum(path_scores) / len(path_scores), 2) if path_scores else 0,
        },
        "violations": {"total": len(violations), "by_severity": by_severity},
        "cost": {"total_estimated": total_cost},
    }


@app.get("/scan/download/{scan_id}/{file_type}")
async def download_scan_data(
    scan_id: str,
    file_type: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Download scan data as JSON or CSV."""
    import glob as _glob

    if file_type not in ("json", "csv"):
        raise HTTPException(status_code=400, detail="file_type must be 'json' or 'csv'")

    # Locate the graph JSON file
    graph_files = _glob.glob(f"/tmp/*{scan_id}*.json")
    if not graph_files:
        # Fallback: look for any provider-prefixed files
        graph_files = [
            f"/tmp/{f}"
            for f in os.listdir("/tmp")
            if f.endswith(".json") and (f.startswith("aws-") or f.startswith("gcp-"))
        ]

    if not graph_files:
        raise HTTPException(status_code=404, detail="Graph data file not found")

    graph_file = sorted(graph_files)[-1]

    if file_type == "json":
        return FileResponse(
            graph_file,
            media_type="application/json",
            filename=f"authmap_scan_{scan_id}.json",
        )

    # CSV generation
    with open(graph_file, "r") as f:
        graph_data = json.load(f)

    output = io.StringIO()
    writer = csv.writer(output)

    # Nodes sheet
    writer.writerow(["type", "id", "name", "provider", "account", "is_admin", "is_overprivileged", "has_mfa", "is_dormant", "is_external", "risk_score"])
    for node in graph_data.get("nodes", []):
        writer.writerow([
            node.get("type", ""),
            node.get("id", ""),
            node.get("name", ""),
            node.get("provider", ""),
            node.get("account", ""),
            node.get("is_admin", False),
            node.get("is_overprivileged", False),
            node.get("has_mfa", False),
            node.get("is_dormant", False),
            node.get("is_external", False),
            node.get("props", {}).get("risk_score", 0),
        ])

    # Blank separator row then edges
    writer.writerow([])
    writer.writerow(["edge_source", "edge_target", "edge_type"])
    for edge in graph_data.get("edges", []):
        writer.writerow([
            edge.get("source", ""),
            edge.get("target", ""),
            edge.get("type", ""),
        ])

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=authmap_scan_{scan_id}.csv"},
    )
