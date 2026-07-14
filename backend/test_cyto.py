import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))
from collectors.scan_orchestrator import ScanOrchestrator
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.DEBUG)
load_dotenv()

uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "password")
postgres_uri = os.getenv("POSTGRES_URI")

orch = ScanOrchestrator(postgres_uri, uri, user, password)
scan_id = '3a369bb7-3105-440f-8805-e13cf692f1d9'
try:
    data = orch.get_graph_for_cytoscape(scan_id)
    print(f"Nodes: {len(data.get('elements', {}).get('nodes', []))}")
except Exception as e:
    import traceback
    traceback.print_exc()
