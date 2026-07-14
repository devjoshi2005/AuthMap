from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()
uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "password")

driver = GraphDatabase.driver(uri, auth=(user, password))
with driver.session() as session:
    res = session.run("MATCH (n:Entity {scan_id: '3a369bb7-3105-440f-8805-e13cf692f1d9'}) RETURN count(n) as c")
    print(f"Nodes for UUID: {res.single()['c']}")
    
    res = session.run("MATCH (n:Entity) RETURN DISTINCT n.scan_id as s")
    print("All scan_ids in Neo4j:")
    for record in res:
        print(f" - {record['s']}")
