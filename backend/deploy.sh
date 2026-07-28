#!/bin/bash


PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No GCP project configured. Please run 'gcloud config set project YOUR_PROJECT_ID'"
    exit 1
fi


if [ -f .env ]; then
    export $(cat .env | xargs)

# Deploy from source using the local Dockerfile
# We allocate 2Gi of RAM to prevent OOM errors with scikit-learn and node2vec
# max-instances=2 prevents accidental billing spikes
gcloud run deploy authmap-backend \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 1 \
  --set-env-vars="FRONTEND_URL=$FRONTEND_URL,CLERK_JWT_ISSUER=$CLERK_JWT_ISSUER,CLERK_SECRET_KEY=$CLERK_SECRET_KEY,POSTGRES_URI=$POSTGRES_URI,GROQ_API_KEY=$GROQ_API_KEY,FONT_DEJAVU_BOLD=$FONT_DEJAVU_BOLD,FONT_DEJAVU_REGULAR=$FONT_DEJAVU_REGULAR,AWS_SCANNER_IAM_POLICY=$AWS_SCANNER_IAM_POLICY,GCP_SCANNER_ROLES=$GCP_SCANNER_ROLES" \
  --min-instances 0 \
  --max-instances 2 \
  --port 8080

