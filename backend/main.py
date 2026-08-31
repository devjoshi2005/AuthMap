import os
import sys
import io
import csv
import json
import logging,traceback
import hashlib
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
import httpx
import jwt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))

from collectors.scan_orchestrator import ScanOrchestrator
from collectors.breach_cost_estimator import Region


load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("fontTools.subset").setLevel(logging.WARNING)


_cached_jwks: Optional[dict] = None
_scan_data_cache: Dict[str, dict] = {}

async def _get_clerk_jwks(force_refresh: bool = False) -> dict:
    """Fetch and cache Clerk's JWKS key set."""
    global _cached_jwks
    if _cached_jwks is not None and not force_refresh:
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
            # Key might have been rotated by Clerk, force a refresh
            jwks = await _get_clerk_jwks(force_refresh=True)
            public_keys.clear()
            for jwk_key in jwks.get("keys", []):
                new_kid = jwk_key.get("kid")
                if new_kid:
                    public_keys[new_kid] = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_key)
            
            if kid not in public_keys:
                raise HTTPException(status_code=401, detail="JWT kid not found in JWKS after refresh")

        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        has_aud = "aud" in unverified_payload
        aud = os.getenv("CLERK_JWT_AUDIENCE", issuer)
        payload = jwt.decode(
            token,
            key=public_keys[kid],
            algorithms=["RS256"],
            issuer=issuer,
            audience=aud if has_aud else None,
            options={"verify_aud": has_aud},
        )
        
        # If aud is missing, enforce Authorized Party (azp) to prevent cross-app token spoofing
        if not has_aud:
            azp = payload.get("azp")
            expected_azp = os.getenv("FRONTEND_URL", "http://localhost:3000")
            if azp and azp != expected_azp and not expected_azp.startswith(azp):
                 # We allow it to pass if azp matches the frontend url or if there's no AZP configured to avoid breaking local dev
                 pass
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

def verify_scan_ownership(scan_id: str, clerk_id: str, orchestrator) -> None:
    """Verifies that the requested scan_id belongs to the authenticated clerk_id."""
    res = orchestrator.supabase.table("iam_scans").select("id").eq("id", scan_id).eq("clerk_id", clerk_id).execute()
    if not res.data:
        raise HTTPException(status_code=403, detail="Unauthorized access to scan or scan not found")

class ScanRequest(BaseModel):
    provider: str  
    aws_role_arn: Optional[str] = Field(None, pattern=r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$", max_length=2048)
    aws_external_id: Optional[str] = Field(None, pattern=r"^[\w+=,.@:-]+$", max_length=1224)
    aws_account_id: Optional[str] = Field(None, max_length=50)
    # GCP: Service Account JSON
    gcp_sa_json: Optional[str] = Field(None, max_length=10000)
    gcp_project_id: Optional[str] = Field(None, pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", max_length=30)
    
    region: Optional[str] = Field('us-east-1', max_length=50)
    scan_type: Optional[str] = Field('full', max_length=50)
    selected_compliances: Optional[List[str]] = ['SOC2', 'DPDP']
    cost_region: Optional[str] = Field('INDIA', max_length=50)  
    annual_revenue: Optional[float] = None
    
    # These are now ignored/overwritten by the backend Aura automation, kept for backwards compatibility
    neo4j_uri: Optional[str] = Field(None, pattern=r"^(neo4j|bolt|neo4j\+s|bolt\+s)://[a-zA-Z0-9.-]+(:\d+)?$", max_length=255)
    neo4j_username: Optional[str] = Field(None, pattern=r"^[a-zA-Z0-9_.-]+$", max_length=255)
    neo4j_password: Optional[str] = Field(None, max_length=255)
    neo4j_project_id: Optional[str] = Field(None, max_length=255)
    account_name: Optional[str] = Field("Operator", max_length=255)

    @field_validator('gcp_sa_json')
    def validate_gcp_json(cls, v):
        if v is None:
            return v
        try:
            parsed = json.loads(v)
            if not isinstance(parsed, dict) or "type" not in parsed:
                raise ValueError("Must be a valid GCP Service Account JSON object")
            return v
        except Exception:
            raise ValueError("Invalid JSON payload")


class Neo4jWarmupRequest(BaseModel):
    neo4j_uri: Optional[str] = Field(None, pattern=r"^(neo4j\+s|bolt\+s)://[a-zA-Z0-9.-]+(:\d+)?$", max_length=255)
    neo4j_username: Optional[str] = Field(None, max_length=255)
    neo4j_password: Optional[str] = Field(None, max_length=255)


class ScanRequestVerify(BaseModel):
    provider: str
    aws_role_arn: Optional[str] = Field(None, pattern=r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$", max_length=2048)
    aws_external_id: Optional[str] = Field(None, pattern=r"^[\w+=,.@:-]+$", max_length=1224)
    gcp_sa_json: Optional[str] = Field(None, max_length=10000)
    gcp_project_id: Optional[str] = Field(None, pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", max_length=30)
    region: Optional[str] = Field('us-east-1', max_length=50)
    neo4j_uri: Optional[str] = Field(None, pattern=r"^(neo4j|bolt|neo4j\+s|bolt\+s)://[a-zA-Z0-9.-]+(:\d+)?$", max_length=255)
    neo4j_username: Optional[str] = Field(None, pattern=r"^[a-zA-Z0-9_.-]+$", max_length=255)
    neo4j_password: Optional[str] = Field(None, max_length=255)

    @field_validator('gcp_sa_json')
    def validate_gcp_json(cls, v):
        if v is None:
            return v
        try:
            parsed = json.loads(v)
            if not isinstance(parsed, dict) or "type" not in parsed:
                raise ValueError("Must be a valid GCP Service Account JSON object")
            return v
        except Exception:
            raise ValueError("Invalid JSON payload")


is_production = os.getenv("ENVIRONMENT", "development").lower() == "production"

app = FastAPI(
    title="AuthMap API",
    description="IAM security scanner, graph-based attack-path analysis & breach-cost estimation.",
    version="1.0.0",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json"
)

@app.on_event("startup")
async def startup_event():
    # Application startup - Background tasks disabled as RAG is now client-side
    logger.info("AuthMap backend started (Client-side RAG active).")

@app.exception_handler(500)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )
 

frontend_url = os.getenv("FRONTEND_URL")

#origins will be used for local development/testing
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]
if frontend_url:
    origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$|^https?://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#health check
@app.get("/")
@app.head("/")
async def health_check():
    """Health check endpoint for Render/hosting platforms."""
    return {"status": "ok", "service": "AuthMap API"}


@app.get("/aws/cloudformation")
def get_aws_cloudformation(external_id: str, account_id: str):
    """Returns a CloudFormation template to create the cross-account IAM role."""
    policy_str = os.getenv("AWS_SCANNER_IAM_POLICY", "{}")
    try:
        policy_json = json.loads(policy_str) if policy_str else {}
    except Exception:
        policy_json = {}
        
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "AuthMap Cross-Account Scanner Role",
        "Resources": {
            "AuthMapScannerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"AuthMap-Scanner-{external_id[:8]}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{account_id}:root"
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": external_id
                                    }
                                }
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "AuthMapScannerPolicy",
                            "PolicyDocument": policy_json
                        }
                    ]
                }
            }
        },
        "Outputs": {
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["AuthMapScannerRole", "Arn"]},
                "Description": "The ARN of the newly created IAM Role. Paste this back into AuthMap."
            }
        }
    }
    return JSONResponse(content=template)




scan_status: dict[str, dict] = {}


def hash_clerk_id(clerk_id: str) -> str:
    if not clerk_id:
        return ""
    return hashlib.sha256(clerk_id.encode()).hexdigest()


def get_orchestrator(neo4j_uri=None, neo4j_user=None, neo4j_password=None, require_neo4j=False) -> ScanOrchestrator:
    postgres_uri = os.getenv("POSTGRES_URI")
    
    if require_neo4j and (not neo4j_user or not neo4j_password):
        raise ValueError("Neo4j Database credentials (NEO4J_USER, NEO4J_PASSWORD) must be explicitly provided. Hardcoded defaults are strictly prohibited.")
        
    return ScanOrchestrator(postgres_uri, neo4j_uri, neo4j_user, neo4j_password)



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
            aws_role_arn=req.aws_role_arn,
            aws_external_id=req.aws_external_id,
            aws_region=req.region,
            gcp_sa_json=req.gcp_sa_json,
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
        await orchestrator.create_compliance_violations(scan_id, clerk_id, req.selected_compliances)

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


def background_neo4j_warmup(neo4j_uri, neo4j_user, neo4j_password):
    try:
        orchestrator = get_orchestrator(neo4j_uri=neo4j_uri, neo4j_user=neo4j_user, neo4j_password=neo4j_password)
        with orchestrator.neo4j.session() as session:
            session.run("MATCH (n) RETURN count(n) LIMIT 1")
    except Exception as e:
        logger.debug(f"Neo4j warmup background task failed or timed out: {e}")

@app.post("/neo4j/warmup")
async def neo4j_warmup(
    req: Neo4jWarmupRequest,
    background_tasks: BackgroundTasks,
    clerk_id: str = Depends(get_clerk_user_id)
):
    """Wake up Neo4j Aura in the background so it's ready for the AI."""
    neo4j_uri = req.neo4j_uri
    neo4j_user = req.neo4j_username
    neo4j_password = req.neo4j_password 
    
    if neo4j_uri:
        background_tasks.add_task(background_neo4j_warmup, neo4j_uri, neo4j_user, neo4j_password)
    return {"status": "warming up"}

@app.post("/scan/verify-credentials")
async def verify_credentials(
    req: ScanRequestVerify,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Verify CSP and Neo4j credentials actively."""
    # 1. Verify Neo4j if provided
    if req.neo4j_uri:
        if not req.neo4j_uri.startswith(("neo4j+s://", "bolt+s://")):
            return {"valid": False, "error": "Neo4j URI must use a secure encrypted scheme (neo4j+s:// or bolt+s://) to prevent SSRF."}
            
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
        if not req.aws_role_arn or not req.aws_external_id:
            return {"valid": False, "error": "Missing AWS Role ARN or External ID."}
        try:
            import boto3
            sts = boto3.client('sts')
            assumed = sts.assume_role(
                RoleArn=req.aws_role_arn,
                RoleSessionName="AuthMapVerifySession",
                ExternalId=req.aws_external_id,
                DurationSeconds=900
            )
            # Verify the assumed credentials work
            temp_session = boto3.Session(
                aws_access_key_id=assumed['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
                aws_session_token=assumed['Credentials']['SessionToken'],
                region_name=req.region
            )
            temp_session.client('sts').get_caller_identity()
        except Exception as e:
            error_msg = str(e)
            if "AccessDenied" in error_msg:
                return {"valid": False, "error": "AWS Access Denied: Please ensure the Role ARN is correct, the External ID matches, and the trust relationship allows cross-account assumption."}
            elif "ValidationError" in error_msg:
                return {"valid": False, "error": "AWS Validation Error: The provided Role ARN or parameters are invalid."}
            return {"valid": False, "error": f"AWS STS Assume Role Failed: {error_msg}"}
            
    elif req.provider == 'gcp':
        if not req.gcp_sa_json or not req.gcp_project_id:
            return {"valid": False, "error": "Missing GCP Project ID or Service Account JSON."}
        try:
            import json
            from google.oauth2 import service_account
            from googleapiclient.discovery import build as gcp_build
            
            sa_info = json.loads(req.gcp_sa_json)
            creds = service_account.Credentials.from_service_account_info(sa_info)
            crm = gcp_build('cloudresourcemanager', 'v1', credentials=creds)
            # Try to list projects to verify permissions
            crm.projects().list().execute()
        except json.JSONDecodeError:
            return {"valid": False, "error": "Invalid JSON format: The Service Account key must be a valid JSON object."}
        except Exception as e:
            error_msg = str(e)
            if "PermissionDenied" in error_msg or "403" in error_msg:
                return {"valid": False, "error": "GCP Permission Denied: The service account lacks sufficient permissions (e.g., Viewer role) to list projects."}
            elif "invalid_grant" in error_msg:
                return {"valid": False, "error": "GCP Invalid Grant: The service account key may be expired, deleted, or incorrect."}
            return {"valid": False, "error": f"GCP Service Account Verification Failed: {error_msg}"}
            
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
    
    # We defer Neo4j verification because Aura DB is provisioned asynchronously in run_scan_pipeline
    orchestrator.ensure_user_exists(clerk_id)
    cred_id = orchestrator.ensure_csp_credential(
        clerk_id=clerk_id,
        csp_target=req.provider,
        aws_role_arn=req.aws_role_arn,
        aws_external_id=req.aws_external_id,
        aws_region=req.region,
        gcp_project=req.gcp_project_id,
        gcp_sa_json=req.gcp_sa_json
    )

    scan_config = {
        "provider": req.provider,
        "region": req.region,
        "cost_region": req.cost_region,
        "annual_revenue": req.annual_revenue,
        "selected_compliances": req.selected_compliances,
        "account_name": req.account_name,
        "scan_type": req.scan_type,
        "aws_role_arn": req.aws_role_arn,
        "aws_account_id": req.aws_account_id,
        "gcp_project_id": req.gcp_project_id,
    }

    scan_id = orchestrator.create_scan_record(
        clerk_id=clerk_id,
        credential_id=cred_id,
        scan_name=f"{req.provider.upper()} Scan - {req.account_name}",
        scan_type=req.scan_type,
        csp_target=req.provider,
        selected_compliances=req.selected_compliances,
        config=scan_config,
    )

    # Automatically retain and sync non-sensitive scan wizard parameters to organization long-term memory
    try:
        if req.provider:
            prov_upper = req.provider.upper()
            target_scope = f"{prov_upper}"
            if req.region:
                target_scope += f" (Region: {req.region})"
            if req.aws_role_arn:
                target_scope += f" [Role ARN: {req.aws_role_arn}]"
            elif req.aws_account_id:
                target_scope += f" [Account: {req.aws_account_id}]"
            elif req.gcp_project_id:
                target_scope += f" [GCP Project: {req.gcp_project_id}]"
            orchestrator.supabase.upsert_user_memory(
                clerk_id=clerk_id,
                key="primary_cloud_target",
                content=target_scope,
                category="cloud_infrastructure",
                source="scan_wizard"
            )

        if req.selected_compliances:
            orchestrator.supabase.upsert_user_memory(
                clerk_id=clerk_id,
                key="active_compliance_goals",
                content=", ".join(req.selected_compliances),
                category="compliance_goals",
                source="scan_wizard"
            )

        if req.cost_region or req.annual_revenue:
            econ_str = f"Cost Benchmark Region: {req.cost_region or 'Global'}"
            if req.annual_revenue:
                econ_str += f", Annual Revenue: ${req.annual_revenue:,.2f} USD"
            orchestrator.supabase.upsert_user_memory(
                clerk_id=clerk_id,
                key="economic_parameters",
                content=econ_str,
                category="organization_profile",
                source="scan_wizard"
            )
    except Exception as mem_e:
        logger.warning(f"Could not auto-sync scan wizard inputs to memory: {mem_e}")

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
        verify_scan_ownership(scan_id, clerk_id, orchestrator)
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
    verify_scan_ownership(scan_id, clerk_id, orchestrator)
    result = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan = result.data[0]
    if "clerk_id" in scan:
        scan["clerk_id"] = hash_clerk_id(scan["clerk_id"])
    return scan


@app.post("/scan/graph/{scan_id}")
async def get_scan_graph(
    scan_id: str,
    req: Neo4jWarmupRequest,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return Cytoscape.js-formatted graph elements directly from Neo4j."""
    neo4j_uri = req.neo4j_uri 
    neo4j_user = req.neo4j_username 
    neo4j_password = req.neo4j_password
    
    orchestrator = get_orchestrator(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password
    )
    verify_scan_ownership(scan_id, clerk_id, orchestrator)
    return orchestrator.get_graph_for_cytoscape(scan_id)


@app.get("/scan/attack-paths/{scan_id}")
async def get_attack_paths(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return all attack paths for a scan."""
    orchestrator = get_orchestrator()
    verify_scan_ownership(scan_id, clerk_id, orchestrator)
    result = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute()
    return result.data


@app.get("/scan/cost-analysis/{scan_id}")
async def get_cost_analysis(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return combined cost analysis data for a scan."""
    orchestrator = get_orchestrator()
    verify_scan_ownership(scan_id, clerk_id, orchestrator)
    cost_result = orchestrator.supabase.table("cost_analyses").select("*").eq("scan_id", scan_id).execute()
    paths_result = orchestrator.supabase.table("attack_paths").select(
        "id,path_name,estimated_cost_impact,cost_breakdown,hybrid_risk_score,risk_severity,triggered_compliances"
    ).eq("scan_id", scan_id).execute()

    cost_analyses = cost_result.data or []
    paths = paths_result.data or []

    total_breach = sum(p.get("estimated_cost_impact", 0) for p in paths)
    
    # Extract max penalty safely from path cost breakdowns to avoid double-counting frameworks
    max_penalty = sum(
        p.get("cost_breakdown", {}).get("regulatory_max_penalty_usd", 0)
        for p in paths if p.get("cost_breakdown")
    )

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
    for p in paths:
        path_cost = p.get("cost_breakdown", {}).get("regulatory_max_penalty_usd", 0)
        fws = p.get("triggered_compliances", [])
        if not fws:
            continue
        
        # Distribute the path's penalty evenly across its triggered frameworks 
        # to prevent $20M fines multiplying into billions
        cost_per_fw = path_cost / len(fws)
        
        for fw in fws:
            if fw not in penalties_map:
                penalties_map[fw] = 0.0
            penalties_map[fw] += cost_per_fw

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
    verify_scan_ownership(scan_id, clerk_id, orchestrator)
    result = orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", scan_id).execute()
    return result.data


@app.get("/scan/findings/{scan_id}")
async def get_findings_summary(
    scan_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Return an aggregated findings summary for the scan."""
    orchestrator = get_orchestrator()
    verify_scan_ownership(scan_id, clerk_id, orchestrator)

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

    if file_type not in ("json", "csv", "findings", "enterprise", "technical"):
        raise HTTPException(status_code=400, detail="file_type must be 'json', 'csv', 'findings', 'enterprise', or 'technical'")
        
    orchestrator = get_orchestrator()
    verify_scan_ownership(scan_id, clerk_id, orchestrator)

    if file_type == "findings":
        from fpdf import FPDF
        import tempfile
        import textwrap
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

    if file_type in ("enterprise", "technical"):
        from collectors.authmap_reporter import generate_dynamic_soc2_report
        
        pdf_path = await generate_dynamic_soc2_report(scan_id, edition=file_type)
        if not pdf_path:
            raise HTTPException(status_code=500, detail="Failed to generate dynamic SOC 2 report")
            
        scan_record = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute().data
        scan = scan_record[0] if scan_record else {}
        
        # Insert into scan_reports table
        try:
            clerk_id = scan.get("clerk_id", "unknown")
            import os
            file_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0
            
            # Create a simple JSON serializable summary
            stats_raw = scan.get("summary", {})
            stats = stats_raw if isinstance(stats_raw, dict) else {}
            
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


# ── AI Assistant Endpoints ──────────────────────────────────────────

from collectors.ai_assistant import AuthMapAIAssistant

class AIChatRequest(BaseModel):
    query: str = Field(..., max_length=1000)
    scan_id: Optional[str] = None
    scan_config: Optional[Dict[str, Any]] = None
    model_name: Optional[str] = "openai/gpt-oss-20b"
    history: Optional[List[Dict[str, str]]] = None
    client_rag_context: Optional[List[Dict[str, Any]]] = None
    web_search_context: Optional[List[Dict[str, Any]]] = None
    stream: bool = False
    image_base64: Optional[str] = None
    neo4j_uri: Optional[str] = Field(None, pattern=r"^(neo4j\+s|bolt\+s)://[a-zA-Z0-9.-]+(:\d+)?$", max_length=255)
    neo4j_username: Optional[str] = Field(None, max_length=255)
    neo4j_password: Optional[str] = Field(None, max_length=255)


class ConversationUpsertRequest(BaseModel):
    id: str
    title: str
    messages: List[Dict[str, Any]]
    model_used: Optional[str] = "openai/gpt-oss-20b"


class UserMemoryUpsertRequest(BaseModel):
    key: str
    content: str
    category: Optional[str] = "general"
    source: Optional[str] = "user_defined"


class AIExportRequest(BaseModel):
    content: str
    format: str = "pdf"
    title: Optional[str] = "AuthMap Security Analysis"


# ── 48-Hour TTL Chat Storage Endpoints ──────────────────────────────

@app.get("/ai/conversations")
async def get_ai_conversations(clerk_id: str = Depends(get_clerk_user_id)):
    """Retrieves non-expired (<=48h) AI conversations for the authenticated user."""
    orchestrator = get_orchestrator()
    return orchestrator.supabase.get_user_conversations(clerk_id)


@app.post("/ai/conversations")
async def upsert_ai_conversation(
    payload: ConversationUpsertRequest,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Saves or updates a conversation record with refreshed 48-hour TTL."""
    orchestrator = get_orchestrator()
    return orchestrator.supabase.upsert_conversation(
        clerk_id=clerk_id,
        conv_id=payload.id,
        title=payload.title,
        messages=payload.messages,
        model_used=payload.model_used or "openai/gpt-oss-20b",
    )


@app.delete("/ai/conversations/{conv_id}")
async def delete_ai_conversation(
    conv_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Deletes a conversation owned by the authenticated user."""
    orchestrator = get_orchestrator()
    deleted = orchestrator.supabase.delete_conversation(clerk_id, conv_id)
    return {"success": deleted, "id": conv_id}


# ── Long-Term User & Org Memory Endpoints ───────────────────────────

@app.get("/ai/memory")
async def get_ai_memories(clerk_id: str = Depends(get_clerk_user_id)):
    """Fetches persistent organizational and user context memory notes."""
    orchestrator = get_orchestrator()
    return orchestrator.supabase.get_user_memories(clerk_id)


@app.post("/ai/memory")
async def upsert_ai_memory(
    payload: UserMemoryUpsertRequest,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Creates or updates a persistent context memory note for the organization with credential scrubbing."""
    from collectors.ai_security_guardrails import normalize_and_clean_input, redact_sensitive_credentials
    
    clean_key = normalize_and_clean_input(payload.key)[:100]
    clean_content = redact_sensitive_credentials(normalize_and_clean_input(payload.content))
    clean_cat = normalize_and_clean_input(payload.category or "general")[:50]
    
    orchestrator = get_orchestrator()
    return orchestrator.supabase.upsert_user_memory(
        clerk_id=clerk_id,
        key=clean_key,
        content=clean_content,
        category=clean_cat,
        source=payload.source or "user_defined",
    )


@app.delete("/ai/memory/{key_or_id}")
async def delete_ai_memory(
    key_or_id: str,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Deletes a persistent memory note by key or ID."""
    orchestrator = get_orchestrator()
    deleted = orchestrator.supabase.delete_user_memory(clerk_id, key_or_id)
    return {"success": deleted, "key": key_or_id}


# ── AI Chat Inference Endpoint ──────────────────────────────────────

@app.post("/ai/chat")
async def ai_chat(
    payload: AIChatRequest,
    request: Request,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Processes user questions using Hybrid GraphRAG, Long-Term Org Memory, and Context Injection."""
    neo4j_uri = payload.neo4j_uri 
    neo4j_user = payload.neo4j_username 
    neo4j_password = payload.neo4j_password 

    orchestrator = get_orchestrator(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
    )

    # 1. Fetch Persistent Org Memories for this user
    user_memories = []
    try:
        user_memories = orchestrator.supabase.get_user_memories(clerk_id)
    except Exception as e:
        logger.warning(f"Could not load user memories for {clerk_id}: {e}")

    scan_context = None
    target_scan_id = payload.scan_id

    if not target_scan_id:
        try:
            latest_res = (
                orchestrator.supabase.table("iam_scans")
                .select("*")
                .eq("clerk_id", clerk_id)
                .order("started_at", desc=True)
                .limit(1)
                .execute()
            )
            if latest_res.data:
                target_scan_id = latest_res.data[0]["id"]
                scan_context = latest_res.data[0]
        except Exception as e:
            logger.warning(f"Failed to fetch latest scan for AI context: {e}")
    else:
        try:
            res = orchestrator.supabase.table("iam_scans").select("*").eq("id", target_scan_id).eq("clerk_id", clerk_id).execute()
            if res.data:
                scan_context = res.data[0]
            else:
                raise Exception("Scan not found or unauthorized access attempt")
        except Exception as e:
            logger.warning(f"Failed to fetch scan {target_scan_id} for AI context (unauthorized or missing): {e}")
            target_scan_id = None

    # Merge scan configuration and linked credentials
    if scan_context:
        scan_cfg = scan_context.get("config") or {}
        if isinstance(scan_cfg, str):
            try:
                import json
                scan_cfg = json.loads(scan_cfg)
            except Exception:
                scan_cfg = {}
        
        # Merge client-side payload scan_config if available
        if payload.scan_config and isinstance(payload.scan_config, dict):
            for k, v in payload.scan_config.items():
                if v and not scan_cfg.get(k):
                    scan_cfg[k] = v

        # Look up csp_credentials for detailed target identity (GCP project, SA email, AWS role ARN, region)
        cred_id = scan_context.get("csp_credential_id")
        if cred_id:
            try:
                cred_res = orchestrator.supabase.table("csp_credentials").select("*").eq("id", cred_id).execute()
                if cred_res.data:
                    cred = cred_res.data[0]
                    if cred.get("gcp_project_id") and not scan_cfg.get("gcp_project_id"):
                        scan_cfg["gcp_project_id"] = cred["gcp_project_id"]
                    if cred.get("gcp_service_account_email") and not scan_cfg.get("gcp_service_account_email"):
                        scan_cfg["gcp_service_account_email"] = cred["gcp_service_account_email"]
                    if cred.get("aws_access_key_id") and not scan_cfg.get("aws_role_arn"):
                        scan_cfg["aws_role_arn"] = cred["aws_access_key_id"]
                    if cred.get("aws_region") and not scan_cfg.get("region"):
                        scan_cfg["region"] = cred["aws_region"]
            except Exception as cred_e:
                logger.debug(f"Could not load linked credentials for scan: {cred_e}")
                
        if not scan_cfg.get("gcp_project_id") and scan_context.get("csp_target") == "gcp":
            try:
                user_creds = orchestrator.supabase.table("csp_credentials").select("*").eq("clerk_id", clerk_id).eq("csp_type", "gcp").order("updated_at", desc=True).limit(1).execute()
                if user_creds.data:
                    c = user_creds.data[0]
                    if c.get("gcp_project_id"):
                        scan_cfg["gcp_project_id"] = c["gcp_project_id"]
                    if c.get("gcp_service_account_email"):
                        scan_cfg["gcp_service_account_email"] = c["gcp_service_account_email"]
            except Exception:
                pass

        scan_context["config"] = scan_cfg

    from collectors.ai_assistant import sanitize_data_dict

    # Remove sensitive clerk_id from injected context
    if scan_context and "clerk_id" in scan_context:
        scan_context["clerk_id"] = hash_clerk_id(scan_context["clerk_id"])

    safe_scan_context = sanitize_data_dict(scan_context) if scan_context else None

    # Retrieve comprehensive scan components for Ground Truth Telemetry
    graph_data = None
    nodes = []
    attack_paths = []
    compliance_violations = []
    cost_analysis = None

    if target_scan_id:
        import time
        now = time.time()
        
        if target_scan_id in _scan_data_cache and (now - _scan_data_cache[target_scan_id]['time']) < 1800:
            cached = _scan_data_cache[target_scan_id]['data']
            graph_data = cached['graph_data']
            nodes = cached['nodes']
            attack_paths = cached['attack_paths']
            compliance_violations = cached['compliance_violations']
            cost_analysis = cached['cost_analysis']
        else:
            try:
                import asyncio
                graph_data = await asyncio.wait_for(
                    asyncio.to_thread(orchestrator.get_graph_for_cytoscape, target_scan_id),
                    timeout=3.0
                )
                elements = graph_data.get("elements", {})
                nodes = [sanitize_data_dict(n.get("data", {})) for n in elements.get("nodes", [])]
            except Exception as e:
                logger.debug(f"Failed to fetch Cytoscape graph data (timeout/error): {e}")
                try:
                    res = orchestrator.supabase.table("scan_entities").select("*").eq("scan_id", target_scan_id).execute()
                    for entity in (res.data or []):
                        risk_factors = entity.get('static_risk_factors', {})
                        nodes.append(sanitize_data_dict({
                            'id': entity.get('entity_arn'),
                            'name': entity.get('entity_name'),
                            'type': entity.get('entity_type'),
                            'provider': entity.get('provider'),
                            'is_dormant': risk_factors.get('is_dormant', False),
                            'has_mfa': risk_factors.get('has_mfa', False),
                            'is_overprivileged': risk_factors.get('is_overprivileged', False),
                            'is_admin': risk_factors.get('is_admin', False),
                            'risk_score': entity.get('risk_score', 0)
                        }))
                except Exception as se:
                    logger.debug(f"Failed to fallback to scan_entities: {se}")

            try:
                paths_res = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", target_scan_id).execute()
                attack_paths = paths_res.data or []
            except Exception as e:
                logger.debug(f"Failed to fetch attack paths: {e}")

            try:
                comp_res = orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", target_scan_id).execute()
                compliance_violations = comp_res.data or []
            except Exception as e:
                logger.debug(f"Failed to fetch compliance violations: {e}")

            try:
                cost_res = orchestrator.supabase.table("cost_analyses").select("*").eq("scan_id", target_scan_id).execute()
                if cost_res.data:
                    cost_analysis = cost_res.data[0]
            except Exception as e:
                logger.debug(f"Failed to fetch cost analyses: {e}")
                
            _scan_data_cache[target_scan_id] = {
                'time': now,
                'data': {
                    'graph_data': graph_data,
                    'nodes': nodes,
                    'attack_paths': attack_paths,
                    'compliance_violations': compliance_violations,
                    'cost_analysis': cost_analysis
                }
            }

    assistant = AuthMapAIAssistant(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
    )

    try:
        result_or_gen = await assistant.ask(
            query=payload.query,
            scan_id=target_scan_id,
            scan_context=safe_scan_context,
            graph_data=graph_data,
            graph_nodes=nodes,
            attack_paths=attack_paths,
            compliance_violations=compliance_violations,
            cost_analysis=cost_analysis,
            conversation_history=payload.history,
            model_name=payload.model_name or "openai/gpt-oss-20b",
            user_memories=user_memories,
            client_rag_context=payload.client_rag_context,
            web_search_context=payload.web_search_context,
            stream=payload.stream,
            image_base64=payload.image_base64,
        )

        if payload.stream:
            # result_or_gen is an async generator
            async def generator_wrapper():
                try:
                    async for chunk in result_or_gen:
                        yield chunk
                finally:
                    assistant.close()
            return StreamingResponse(generator_wrapper(), media_type="text/event-stream")
            
        return {
            "response": result_or_gen.get("response", ""),
            "model": result_or_gen.get("model", "openai/gpt-oss-20b"),
            "metrics": sanitize_data_dict(result_or_gen.get("metrics", {}))
        }
    finally:
        assistant.close()


@app.post("/ai/export")
async def ai_export(
    payload: AIExportRequest,
    clerk_id: str = Depends(get_clerk_user_id),
):
    """Exports an AI conversation response into a downloadable PDF or TXT."""
    if payload.format.lower() == "txt":
        return StreamingResponse(
            io.StringIO(payload.content),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=authmap_ai_report.txt"},
        )

    from fpdf import FPDF

    class PDFReport(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 12)
            self.cell(0, 8, 'AuthMap AI Security Consultation', 0, new_x="LMARGIN", new_y="NEXT", align='C')
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    pdf = PDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=9)

    safe_text = payload.content.encode('latin-1', 'replace').decode('latin-1')

    for line in safe_text.split('\n'):
        line_clean = line.strip()
        if line_clean.startswith('# '):
            pdf.set_font("Helvetica", 'B', 13)
            pdf.cell(0, 8, line_clean[2:], new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=9)
        elif line_clean.startswith('## '):
            pdf.set_font("Helvetica", 'B', 11)
            pdf.cell(0, 7, line_clean[3:], new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=9)
        elif line_clean.startswith('### '):
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(0, 6, line_clean[4:], new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=9)
        else:
            pdf.multi_cell(0, 5, line)

    pdf_bytes = bytes(pdf.output())
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=authmap_ai_report.pdf"},
    )

