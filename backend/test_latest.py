import asyncio
from collectors.database import PostgresClient
import os
from dotenv import load_dotenv

load_dotenv()
postgres_uri = os.getenv("POSTGRES_URI")

client = PostgresClient(postgres_uri)
res = client.table("iam_scans").select("*").order("started_at", desc=True).limit(1).execute()
print(res.data)
