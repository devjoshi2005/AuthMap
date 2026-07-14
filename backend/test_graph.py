import json
import glob
import os

def test():
    files = glob.glob('/tmp/*.json')
    print("Files in /tmp:")
    for f in files:
        if 'aws' in f or 'gcp' in f or 'scan' in f:
            print(f" - {f}")
            with open(f, 'r') as fp:
                data = json.load(fp)
                nodes = data.get('nodes', [])
                edges = data.get('edges', [])
                print(f"   Nodes: {len(nodes)}, Edges: {len(edges)}")
                if len(nodes) > 0:
                    print(f"   First node keys: {list(nodes[0].keys())}")
                    
test()
