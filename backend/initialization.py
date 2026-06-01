from dotenv import load_dotenv
import os
from typing import Optional,AsyncGenerator,Sequence
from sqlmodel import SQLModel, Field
from fastapi import FastAPI, Depends, HTTPException, Request, APIRouter
from fastapi.responses import Response, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import create_async_engine
from contextlib import asynccontextmanager
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker 
from sqlmodel import select,text
from pydantic import BaseModel
from module1_prompt_injection import run_prompt_injection_scan
from pdf_generator import generate_ai_report, generate_remediation_pdf
import time
import aiofiles

os.makedirs("./reports", exist_ok=True)

load_dotenv()

uri = os.getenv('POSTGRES_URI').replace("postgresql://", "postgresql+asyncpg://")



class Scan_Data(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: str = Field(nullable=False)
    compliance_pdf_path: str = Field(default="")
    remediation_pdf_path: str = Field(default="")
    findings_txt_path: str = Field(default="")

class ScanRequest(BaseModel):
    url: str
    tier: str
    llm_provider: str = "openai"
    api_key: str = ""

class VerifyKeyRequest(BaseModel):
    provider: str
    api_key: str



security = HTTPBearer()
clerk_jwks_cache: dict[str, dict] = {}


async def get_clerk_jwks(issuer: str, force_refresh: bool = False) -> dict:
    normalized_issuer = issuer.rstrip("/")

    if not force_refresh and normalized_issuer in clerk_jwks_cache:
        return clerk_jwks_cache[normalized_issuer]

    jwks_url = os.getenv("CLERK_JWKS_URL") or f"{normalized_issuer}/.well-known/jwks.json"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(jwks_url)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Unable to verify token") from exc

    jwks = response.json()
    if not isinstance(jwks, dict) or "keys" not in jwks:
        raise HTTPException(status_code=503, detail="Unable to verify token")

    clerk_jwks_cache[normalized_issuer] = jwks
    return jwks


async def decode_clerk_token(token: str, issuer: str, force_refresh: bool = False) -> dict:
    jwks = await get_clerk_jwks(issuer, force_refresh=force_refresh)
    return jwt.decode(
        token,
        jwks,
        algorithms=["RS256"],
        issuer=issuer,
        options={"verify_aud": False},
    )

async def get_current_user_id(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        unverified_claims = jwt.get_unverified_claims(token)
    except JWTError as exc:
        print(f"[AUTH ERROR] Failed to get unverified claims: {exc}")
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    issuer = unverified_claims.get("iss")
    if not issuer:
        print("[AUTH ERROR] Token missing 'iss' claim")
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        claims = await decode_clerk_token(token, issuer)
    except JWTError:
        try:
            claims = await decode_clerk_token(token, issuer, force_refresh=True)
        except JWTError as exc:
            print(f"[AUTH ERROR] Failed to decode token: {exc}")
            raise HTTPException(status_code=401, detail="Invalid token") from exc

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user_id
        


#creating a async engine
engine = create_async_engine(uri, echo=False, connect_args={
        "prepared_statement_cache_size": 0,  
        "statement_cache_size": 0           
    })
async_session= sessionmaker(engine,class_=AsyncSession,expire_on_commit=False)

async def verify_connection():
    try:
        async with AsyncSession(engine) as session:
            result = await session.exec(text('SELECT 1'))
            print("conn success",result.scalar())
    except Exception as e:
        print("connection failed",e)


async def get_session() -> AsyncGenerator[AsyncSession,None]:
    async with async_session() as session:
        yield session

@asynccontextmanager
async def lifespan(app: FastAPI):
    # create tables on startup only if they don't already exist (checkfirst=True is the default)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    print("[STARTUP] Tables verified (created only if missing).")
    yield 
    await engine.dispose()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://boxai-v1.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter()


@router.post("/keys/verify")
async def verify_api_key(req: VerifyKeyRequest, user_id: str = Depends(get_current_user_id)):
    provider = req.provider.lower()
    api_key = req.api_key.strip()
    
    if not api_key:
        raise HTTPException(status_code=400, detail="API key is required")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if provider == "openai":
                res = await client.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {api_key}"})
                if res.status_code != 200:
                    raise HTTPException(status_code=401, detail="Invalid OpenAI API Key")
            elif provider == "anthropic":
                res = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                    json={"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}
                )
                if res.status_code == 401 or res.status_code == 403:
                    raise HTTPException(status_code=401, detail="Invalid Anthropic API Key")
            elif provider == "gemini":
                res = await client.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}")
                if res.status_code != 200:
                    raise HTTPException(status_code=401, detail="Invalid Gemini API Key")
            else:
                raise HTTPException(status_code=400, detail="Unsupported provider")
                
            return {"status": "ok", "message": "Valid API Key"}
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail="Failed to connect to provider API")
            

@router.post("/scan/run")
async def run_scan(scan_request: ScanRequest,
                   session: AsyncSession = Depends(get_session),
                   user_id: str = Depends(get_current_user_id)) -> Scan_Data:
    if not scan_request.url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http or https.")
    if scan_request.tier not in ["small", "avg", "big"]:
         scan_request.tier = "small"
    
    try:
        outputs, remediation = await run_prompt_injection_scan(scan_request.url, scan_request.tier, scan_request.llm_provider, scan_request.api_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to run scan: {str(e)}")
        
    ts = int(time.time())
    
    findings_path = f"./reports/findings_{user_id}_{ts}.txt"
    async with aiofiles.open(findings_path, mode="w", encoding="utf-8") as f:
        await f.write(outputs)
        
    comp_pdf_bytes = generate_ai_report(ts, scan_request.url, scan_request.tier, outputs, remediation)
    compliance_path = f"./reports/compliance_{user_id}_{ts}.pdf"
    async with aiofiles.open(compliance_path, mode="wb") as f:
        await f.write(comp_pdf_bytes)
        
    rem_pdf_bytes = generate_remediation_pdf(remediation)
    remediation_path = f"./reports/remediation_{user_id}_{ts}.pdf"
    async with aiofiles.open(remediation_path, mode="wb") as f:
        await f.write(rem_pdf_bytes)
    
    db_scan = Scan_Data(
        user_id=user_id,
        findings_txt_path=findings_path,
        compliance_pdf_path=compliance_path,
        remediation_pdf_path=remediation_path
    )
    session.add(db_scan)
    await session.commit()
    await session.refresh(db_scan)
    return db_scan

@router.get("/scan/results/latest")
async def get_latest_scan(session: AsyncSession = Depends(get_session),
                          user_id: str = Depends(get_current_user_id)) -> Scan_Data:
    statement = select(Scan_Data).where(Scan_Data.user_id == user_id).order_by(Scan_Data.id.desc())
    result = await session.exec(statement)
    doc = result.first()
    if not doc:
        raise HTTPException(status_code=404, detail="No scan results found")
    return doc

@router.get("/scan/download/{scan_id}/{file_type}")
async def download_file(scan_id: int, file_type: str, 
                        session: AsyncSession = Depends(get_session),
                        user_id: str = Depends(get_current_user_id)):
    statement = select(Scan_Data).where(Scan_Data.id == scan_id, Scan_Data.user_id == user_id)
    result = await session.exec(statement)
    doc = result.one_or_none()
    
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    path_map = {
        "compliance": doc.compliance_pdf_path,
        "remediation": doc.remediation_pdf_path,
        "findings": doc.findings_txt_path
    }
    
    file_path = path_map.get(file_type)
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File does not exist")
        
    return FileResponse(path=file_path, filename=os.path.basename(file_path))

app.include_router(router)
