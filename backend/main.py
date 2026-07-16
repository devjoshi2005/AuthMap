import os
import sys
import io
import csv
import json
import logging
import hashlib
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx
import jwt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))

from collectors.scan_orchestrator import ScanOrchestrator
from collectors.breach_cost_estimator import Region


load_dotenv()
logger = logging.getLogger(__name__)
logging.getLogger("fontTools.subset").setLevel(logging.WARNING)


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
        public_keys: dict[str, jwt.algorithms.RSAAlgorithm] = {}
        for jwk_key in jwks.get("keys", []):
            kid = jwk_key.get("kid")
            if kid:
                public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_key)

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



class ScanRequest(BaseModel):
    provider: str  
    aws_access_key_id: Optional[str] = None
    aws_secret_key: Optional[str] = None
    region: Optional[str] = 'us-east-1'
    gcp_project_id: Optional[str] = None
    gcp_service_account_key: Optional[str] = None
    scan_type: Optional[str] = 'full'
    selected_compliances: Optional[List[str]] = ['SOC2', 'DPDP']
    cost_region: Optional[str] = 'INDIA'  
    annual_revenue: Optional[float] = None
    neo4j_uri: Optional[str] = None
    neo4j_username: Optional[str] = None
    neo4j_password: Optional[str] = None
    neo4j_project_id: Optional[str] = None
    account_name: Optional[str] = "Operator"


class ScanRequestVerify(BaseModel):
    provider: str
    aws_access_key_id: Optional[str] = None
    aws_secret_key: Optional[str] = None
    region: Optional[str] = 'us-east-1'
    gcp_project_id: Optional[str] = None
    gcp_service_account_key: Optional[str] = None
    neo4j_uri: Optional[str] = None
    neo4j_username: Optional[str] = None
    neo4j_password: Optional[str] = None


app = FastAPI(
    title="AuthMap API",
    description="IAM security scanner, graph-based attack-path analysis & breach-cost estimation.",
    version="0.1.0",
)

frontend_url = os.getenv("FRONTEND_URL")
origins = ["http://localhost:3000", "http://localhost:3001"]
if frontend_url:
    origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
@app.head("/")
async def health_check():
    """Health check endpoint for Render/hosting platforms."""
    return {"status": "ok", "service": "AuthMap API"}


scan_status: dict[str, dict] = {}


def hash_clerk_id(clerk_id: str) -> str:
    if not clerk_id:
        return ""
    return hashlib.sha256(clerk_id.encode()).hexdigest()


def get_orchestrator(neo4j_uri=None, neo4j_user=None, neo4j_password=None) -> ScanOrchestrator:
    """Instantiate a ScanOrchestrator with env-var defaults (overridable)."""
    postgres_uri = os.getenv("POSTGRES_URI")
    n_uri = neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
    n_user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
    n_pass = neo4j_password or os.getenv("NEO4J_PASSWORD", "password")
    return ScanOrchestrator(postgres_uri, n_uri, n_user, n_pass)



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
        scan_status[scan_id].update(phase="compliance", progress=75)
        orchestrator.create_compliance_violations(scan_id, clerk_id, req.selected_compliances)

        # Phase 5 — AI Remediation
        scan_status[scan_id].update(phase="remediation", progress=85)
        await orchestrator.create_remediations(scan_id)

        # Phase 6 — Finalize
        scan_status[scan_id].update(phase="reporting", progress=95)
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


@app.post("/scan/verify-credentials")
async def verify_credentials(
    req: ScanRequestVerify,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Verify CSP and Neo4j credentials actively."""
    # 1. Verify Neo4j if provided
    if req.neo4j_uri:
        orchestrator = get_orchestrator(
            neo4j_uri=req.neo4j_uri,
            neo4j_user=req.neo4j_username,
            neo4j_password=req.neo4j_password,
        )
        try:
            orchestrator.verify_neo4j_connection()
        except Exception as e:
            return {"valid": False, "error": f"Neo4j Connection Failed: {str(e)}"}
            
    # 2. Verify CSP
    if req.provider == 'aws':
        if not req.aws_access_key_id or not req.aws_secret_key:
            return {"valid": False, "error": "Missing AWS credentials."}
        try:
            import boto3
            client = boto3.client(
                'sts',
                aws_access_key_id=req.aws_access_key_id,
                aws_secret_access_key=req.aws_secret_key,
                region_name=req.region
            )
            client.get_caller_identity()
        except Exception as e:
            return {"valid": False, "error": f"AWS Authentication Failed: {str(e)}"}
            
    elif req.provider == 'gcp':
        if not req.gcp_service_account_key:
            return {"valid": False, "error": "Missing GCP Service Account JSON."}
        try:
            import json
            from google.oauth2 import service_account
            
            creds_info = json.loads(req.gcp_service_account_key)
            service_account.Credentials.from_service_account_info(creds_info)
        except Exception as e:
            return {"valid": False, "error": f"GCP Authentication Failed: {str(e)}"}
            
    return {"valid": True, "error": None}


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
    
    try:
        orchestrator.verify_neo4j_connection()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    orchestrator.ensure_user_exists(clerk_id)
    cred_id = orchestrator.ensure_csp_credential(
        clerk_id=clerk_id,
        csp_target=req.provider,
        aws_access=req.aws_access_key_id,
        aws_secret=req.aws_secret_key,
        aws_region=req.region,
        gcp_project=req.gcp_project_id,
        gcp_json=req.gcp_service_account_key
    )

    scan_id = orchestrator.create_scan_record(
        clerk_id=clerk_id,
        credential_id=cred_id,
        scan_name=f"{req.provider.upper()} Scan - {req.account_name}",
        scan_type=req.scan_type,
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
    
    scan = result.data[0]
    if "clerk_id" in scan:
        scan["clerk_id"] = hash_clerk_id(scan["clerk_id"])
    return scan


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
        
    scan = result.data[0]
    if "clerk_id" in scan:
        scan["clerk_id"] = hash_clerk_id(scan["clerk_id"])
    return scan


@app.get("/scan/graph/{scan_id}")
async def get_scan_graph(
    scan_id: str,
    request: Request,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return Cytoscape.js-formatted graph elements directly from Neo4j."""
    neo4j_uri = request.headers.get("x-neo4j-uri")
    neo4j_user = request.headers.get("x-neo4j-user")
    neo4j_password = request.headers.get("x-neo4j-password")
    
    orchestrator = get_orchestrator(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password
    )
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
        "id,path_name,estimated_cost_impact,cost_breakdown,hybrid_risk_score,risk_severity,triggered_compliances"
    ).eq("scan_id", scan_id).execute()

    cost_analyses = cost_result.data or []
    paths = paths_result.data or []

    total_breach = sum(p.get("estimated_cost_impact", 0) for p in paths)
    max_penalty = sum(ca.get("regulatory_fine_cost", 0) for ca in cost_analyses)
    record_costs = [p.get("cost_breakdown", {}).get("final_per_record_cost_usd") for p in paths if p.get("cost_breakdown") and p["cost_breakdown"].get("final_per_record_cost_usd")]
    avg_per_record = sum(record_costs) / len(record_costs) if record_costs else 165.0
    max_risk_score = max([p.get("hybrid_risk_score", 0) for p in paths] + [0])

    frontend_paths = []
    for p in paths:
        frontend_paths.append({
            "path_id": p.get("id"),
            "path": p.get("path_name", ""),
            "risk_score": p.get("hybrid_risk_score", 0),
            "estimated_cost": p.get("estimated_cost_impact", 0),
            "compliance": p.get("triggered_compliances", []),
            "severity": p.get("risk_severity", "low")
        })
        
    penalties_map = {}
    for ca in cost_analyses:
        fw = ca.get("compliance_framework")
        if not fw:
            continue
        # Use regulatory fine if available, fallback to total estimated
        cost = float(ca.get("regulatory_fine_cost") or ca.get("total_estimated_cost", 0))
        if fw not in penalties_map:
            penalties_map[fw] = 0.0
        penalties_map[fw] += cost

    penalties = []
    for fw, total_cost in penalties_map.items():
        penalties.append({
            "framework": fw,
            "penalty_low": total_cost * 0.5,
            "penalty_high": total_cost
        })

    return {
        "total_estimated_breach_cost": total_breach,
        "max_regulatory_penalty": max_penalty,
        "avg_per_record_cost": avg_per_record,
        "max_risk_score": max_risk_score,
        "paths": frontend_paths,
        "compliance_penalties": penalties,
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
        "entities": {
            "total": len(entities),
            "users": by_type.get("user", 0),
            "roles": by_type.get("role", 0),
            "groups": by_type.get("group", 0),
            "policies": by_type.get("managed_policy", 0),
            "service_accounts": by_type.get("service_account", 0),
        },
        "risk": {
            "admin_count": admin_count,
            "overprivileged_count": overprivileged_count,
            "dormant_count": dormant_count,
        },
        "attack_paths": {
            "total": len(paths),
            "max_risk_score": max(path_scores, default=0),
            "avg_risk_score": round(sum(path_scores) / len(path_scores), 2) if path_scores else 0,
        },
        "compliance_violations": {
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
        },
        "total_estimated_breach_cost": total_cost,
    }


@app.get("/scan/download/{scan_id}/{file_type}")
async def download_scan_data(
    scan_id: str,
    file_type: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    import glob as _glob

    if file_type not in ("json", "csv", "findings", "enterprise"):
        raise HTTPException(status_code=400, detail="file_type must be 'json', 'csv', 'findings', or 'enterprise'")

    if file_type == "findings":
        from fpdf import FPDF
        import tempfile
        import textwrap
        
        orchestrator = get_orchestrator()
        scan_res = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute()
        scan_name = scan_res.data[0].get("scan_name", "Unknown Account") if scan_res.data else "Unknown Account"
        
        if " - " in scan_name:
            account_name = scan_name.split(" - ")[-1]
        else:
            account_name = scan_name

        paths_res = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute()
        paths = paths_res.data or []
        
        pdf = FPDF()
        pdf.add_page()
        pdf.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
        pdf.add_font("DejaVu", "B", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
        
        pdf.set_font("DejaVu", "B", 16)
        pdf.cell(0, 10, f"IAM Security Analysis - SCAN {account_name}", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(10)
        
        if not paths:
            pdf.set_font("DejaVu", "", 12)
            pdf.cell(0, 10, "No attack paths found in this scan. Note: You may need to run a new scan.", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_font("DejaVu", "B", 14)
            pdf.cell(0, 10, f"Total Attack Paths: {len(paths)}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            
            for i, p in enumerate(paths, 1):
                pdf.set_font("DejaVu", "B", 12)
                safe_name = textwrap.fill(str(p.get('path_name', 'Unknown Path')), width=60, break_long_words=True)
                pdf.set_x(10)
                pdf.multi_cell(190, 7, f"{i}. {safe_name}")
                
                pdf.set_font("DejaVu", "", 10)
                safe_desc = textwrap.fill(str(p.get('path_description', '')), width=60, break_long_words=True)
                pdf.set_x(10)
                pdf.multi_cell(190, 7, f"Description: {safe_desc}")
                
                safe_sev = textwrap.fill(f"Risk Severity: {p.get('risk_severity', 'Unknown').upper()} | Score: {p.get('hybrid_risk_score', 0):.2f}", width=60, break_long_words=True)
                pdf.set_x(10)
                pdf.multi_cell(190, 7, safe_sev)
                
                safe_cost = textwrap.fill(f"Est. Breach Cost: ${p.get('estimated_cost_impact', 0):,.2f}", width=60, break_long_words=True)
                pdf.set_x(10)
                pdf.multi_cell(190, 7, safe_cost)
                pdf.ln(5)
                
        tmp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        pdf.output(tmp_pdf.name)
        
        return FileResponse(
            tmp_pdf.name,
            media_type="application/pdf",
            filename=f"authmap_findings_{scan_id}.pdf"
        )

    if file_type == "enterprise":
        from remediation_engine import EnterpriseReportGenerator
        
        orchestrator = get_orchestrator()
        
        # Gather report data
        scan_record = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute().data
        scan = scan_record[0] if scan_record else {}
        
        paths_res = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute()
        paths = paths_res.data or []
        
        violations_res = orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", scan_id).execute()
        violations = violations_res.data or []
        
        stats = {
            "total_nodes": scan.get("total_entities", 0),
            "total_paths": len(paths),
            "max_risk": max([p.get('hybrid_risk_score', 0) for p in paths] + [0]),
            "breach_cost": sum([p.get('estimated_cost_impact', 0) for p in paths])
        }
        
        formatted_paths = []
        for p in paths:
            nodes = p.get('path_nodes', {})
            node_list = nodes.get('nodes', []) if isinstance(nodes, dict) else (nodes if isinstance(nodes, list) else [])
            
            formatted_paths.append({
                "name": p.get('path_name', 'Unknown Path'),
                "risk_score": p.get('hybrid_risk_score', 0),
                "cost": p.get('estimated_cost_impact', 0),
                "nodes": node_list,
                "remediation": p.get('remediation_json')
            })
            
        report_data = {
            "date": scan.get("created_at", ""),
            "frameworks": scan.get("selected_compliances", []),
            "stats": stats,
            "compliance_violations": violations,
            "attack_paths": formatted_paths
        }
        
        generator = EnterpriseReportGenerator()
        pdf_path = generator.generate_pdf(scan_id, report_data)
        
        # Insert into scan_reports table
        try:
            clerk_id = scan.get("clerk_id", "unknown")
            file_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0
            
            # Create a simple JSON serializable summary
            safe_stats = {
                "total_nodes": int(stats.get("total_nodes", 0)),
                "total_paths": int(stats.get("total_paths", 0)),
                "max_risk": float(stats.get("max_risk", 0)),
                "breach_cost": float(stats.get("breach_cost", 0))
            }
            
            orchestrator.supabase.table("scan_reports").insert({
                "scan_id": scan_id,
                "clerk_id": clerk_id,
                "report_type": "executive_summary",
                "report_format": "pdf",
                "storage_path": pdf_path,
                "file_size_bytes": file_size,
                "summary": safe_stats
            }).execute()
        except Exception as e:
            logger.error(f"Failed to insert scan_reports record: {e}")
        
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"authmap_enterprise_report_{scan_id}.pdf"
        )

    graph_data = orchestrator.get_graph_for_cytoscape(scan_id)
    elements = graph_data.get("elements", {})
    nodes = [n.get("data", {}) for n in elements.get("nodes", [])]
    edges = [e.get("data", {}) for e in elements.get("edges", [])]
    
    if not nodes and not edges:
        raise HTTPException(status_code=404, detail="Graph data not found in Neo4j")

    if file_type == "json":
        return StreamingResponse(
            io.StringIO(json.dumps({"nodes": nodes, "edges": edges})),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=authmap_scan_{scan_id}.json"},
        )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["type", "id", "name", "provider", "account", "is_admin", "is_overprivileged", "has_mfa", "is_dormant", "is_external", "risk_score"])
    for node in nodes:
        writer.writerow([
            node.get("type", ""),
            node.get("id", ""),
            node.get("label", ""),
            node.get("provider", ""),
            node.get("account", ""),
            node.get("is_admin", False),
            node.get("is_overprivileged", False),
            node.get("has_mfa", False),
            node.get("is_dormant", False),
            node.get("is_external", False),
            node.get("risk_score", 0),
        ])

    writer.writerow([])
    writer.writerow(["edge_source", "edge_target", "edge_type"])
    for edge in edges:
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
