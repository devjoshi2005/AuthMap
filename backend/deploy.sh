#!/bin/bash

PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No GCP project configured. Please run 'gcloud config set project YOUR_PROJECT_ID'"
    exit 1
fi

if [ -f .env ]; then
    # Safely convert .env to env.yaml to avoid bash escaping and comma-delimiting issues
    python3 -c '
import json
from dotenv import dotenv_values
d = dotenv_values(".env")
with open("env.yaml", "w") as f:
    for k, v in d.items():
        if v is not None:
            f.write(f"{k}: {json.dumps(v)}\n")
'
fi

# Deploy from source using the local Dockerfile
# We allocate 2Gi of RAM to prevent OOM errors with scikit-learn and node2vec
# max-instances=2 prevents accidental billing spikes
gcloud run deploy authmap-backend \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 1 \
  --env-vars-file=env.yaml \
  --min-instances 0 \
  --max-instances 2 \
  --port 8080

# Clean up temporary yaml
rm -f env.yaml
