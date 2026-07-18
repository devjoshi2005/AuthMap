#!/bin/bash

# AuthMap Backend - GCP Cloud Run Deployment Script
# This script deploys the backend to Cloud Run using the existing Dockerfile.

PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No GCP project configured. Please run 'gcloud config set project YOUR_PROJECT_ID'"
    exit 1
fi

echo "Deploying AuthMap Backend to Google Cloud Run..."
echo "Project: $PROJECT_ID"
echo "Region: us-central1 (Tier 1 Free Tier Eligible, Lowest Latency)"

# Deploy from source using the local Dockerfile
# We allocate 2Gi of RAM to prevent OOM errors with scikit-learn and node2vec
# max-instances=2 prevents accidental billing spikes
gcloud run deploy authmap-backend \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 1 \
  --set-env-vars="FRONTEND_URL=https://authmap.vercel.app" \
  --min-instances 0 \
  --max-instances 2 \
  --port 8080

echo "========================================="
echo "✅ Deployment complete!"
echo "Please copy the Service URL provided above."
echo "========================================="
