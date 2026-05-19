from dotenv import load_dotenv
import os
from typing import Optional,AsyncGenerator,Sequence
from sqlmodel import SQLModel, Field
from fastapi import FastAPI, Depends, HTTPException, Request,APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import create_async_engine
from contextlib import asynccontextmanager
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker 
from sqlmodel import select,text


load_dotenv()

uri = os.getenv('POSTGRES_URI').replace("postgresql://", "postgresql+asyncpg://")



class Scan_DataCreate(SQLModel):
    terraform_code_file: str
    compliance_report_file: str


class Scan_Data(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    terraform_code_file: str = Field(nullable=False) 
    compliance_report_file: str = Field(nullable=False)
    user_id: str = Field(nullable=False)

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
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    issuer = os.getenv("CLERK_JWT_ISSUER") or unverified_claims.get("iss")
    if not issuer:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        claims = await decode_clerk_token(token, issuer)
    except JWTError:
        try:
            claims = await decode_clerk_token(token, issuer, force_refresh=True)
        except JWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid token") from exc

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user_id
        


#creating a async engine
engine = create_async_engine(uri, echo=True,connect_args={
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
    # create table on startup stage if doesnt exist
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield 
    await engine.dispose()

app = FastAPI(lifespan=lifespan)
router = APIRouter()
app.include_router(router)


@router.post("/documents/")
async def insert_documents(scan_data : Scan_DataCreate,
                           session:AsyncSession=Depends(get_session),
                           user_id:str=Depends(get_current_user_id)) -> Scan_Data:
    db_scan_data = Scan_Data(terraform_code_file=scan_data.terraform_code_file,
                            compliance_report_file=scan_data.compliance_report_file,
                            user_id=user_id)
    session.add(db_scan_data)
    await session.commit()
    await session.refresh(db_scan_data)
    return db_scan_data 

@router.get("/documents/")
async def read_document(session:AsyncSession=Depends(get_session),
                        user_id : str = Depends(get_current_user_id)) -> Sequence[Scan_Data]:
    statement = select(Scan_Data).where(Scan_Data.user_id==user_id)
    result = await session.exec(statement)                            
    return result.all()

@router.delete("/documents/{doc_id}")
async def delete_document(doc_id:int,
                          session:AsyncSession=Depends(get_session),
                          user_id : str=Depends(get_current_user_id)):
    statement = select(Scan_Data).where(Scan_Data.id==doc_id,Scan_Data.user_id==user_id)
    result = await session.exec(statement)
    db_scan_data = result.one_or_none()
    if not db_scan_data:
        raise HTTPException(status_code=404,detail="Document not found")
    await session.delete(db_scan_data)
    await session.commit()
    return {"message":"Document deleted"}

