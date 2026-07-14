import asyncio
from scan_orchestrator import ScanOrchestrator
import os
from dotenv import load_dotenv

load_dotenv()
uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "password")
supabase_url = os.getenv("SUPABASE_URL")

orch = ScanOrchestrator(supabase_url, uri, user, password)

# Fetch from Neo4j direct to get a valid scan_id
with orch.neo4j.session() as session:
    res = session.run("MATCH (n:Entity) RETURN n.scan_id as s LIMIT 1")
    scan_id = res.single()['s']
    print(f"Testing with scan_id: {scan_id}")

data = orch.get_graph_for_cytoscape(scan_id)
print(f"Nodes: {len(data.get('elements', {}).get('nodes', []))}")
print(f"Edges: {len(data.get('elements', {}).get('edges', []))}")
