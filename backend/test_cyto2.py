import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))
from collectors.scan_orchestrator import ScanOrchestrator
from dotenv import load_dotenv

load_dotenv()
uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "password")
postgres_uri = os.getenv("POSTGRES_URI")

orch = ScanOrchestrator(postgres_uri, uri, user, password)
scan_id = '3a369bb7-3105-440f-8805-e13cf692f1d9'

cyto_nodes = []
cyto_edges = []
with orch.neo4j.session() as session:
    result = session.run("MATCH (n:Entity {scan_id: $scan_id}) RETURN n", scan_id=scan_id)
    for record in result:
        node = record['n']
        props_str = node.get('props', '{}')
        props_dict = json.loads(props_str) if isinstance(props_str, str) else props_str
        
        cyto_nodes.append({
            "data": {
                "id": node.get('id', ''),
                "risk_score": max(
                    props_dict.get('risk_score', 0) if isinstance(props_dict, dict) else 0,
                    0
                )
            }
        })
    print(f"Nodes: {len(cyto_nodes)}")

    result = session.run(
        "MATCH (n:Entity {scan_id: $scan_id})-[r]->(m:Entity {scan_id: $scan_id}) "
        "RETURN n.id AS source, m.id AS target, type(r) AS rel_type, r", 
        scan_id=scan_id
    )
    for record in result:
        source = record['source']
        target = record['target']
        rel_type = record['rel_type']
        r = record['r']
        cyto_edges.append({
            "data": {
                "id": f"{source}->{target}",
                "source": source,
                "target": target,
                "label": rel_type,
                "type": r.get('type', rel_type),
            }
        })
    print(f"Edges: {len(cyto_edges)}")
