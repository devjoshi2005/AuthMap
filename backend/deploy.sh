#!/bin/bash

# AuthMap Backend - AWS ECS Fargate deployment
# Low-cost footprint: smallest Fargate task (0.25 vCPU / 512 MB); cold start acceptable.
# Security guardrails ON by default: AUTHMAP_SECURITY_ENABLED=true (see backend/Dockerfile).
#
# Required environment:
#   AWS_ACCOUNT_ID, TASK_ROLE_ARN, EXECUTION_ROLE_ARN
# Optional overrides:
#   AWS_REGION, ECS_CLUSTER, ECS_SERVICE, TASK_FAMILY, ECR_REPOSITORY,
#   IMAGE_TAG, TASK_CPU, TASK_MEMORY, CONTAINER_PORT

set -euo pipefail

AWS_REGION="${AWS_REGION:-ap-south-1}"
ECS_CLUSTER="${ECS_CLUSTER:-authmap-cluster}"
ECS_SERVICE="${ECS_SERVICE:-authmap-backend}"
TASK_FAMILY="${TASK_FAMILY:-authmap-backend}"
ECR_REPOSITORY="${ECR_REPOSITORY:-authmap-backend}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
CONTAINER_PORT="${CONTAINER_PORT:-8000}"
TASK_CPU="${TASK_CPU:-256}"
TASK_MEMORY="${TASK_MEMORY:-512}"
SECURITY_ENABLED="${SECURITY_ENABLED:-true}"
TASK_ROLE_ARN="${TASK_ROLE_ARN:-}"
EXECUTION_ROLE_ARN="${EXECUTION_ROLE_ARN:-}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"

if [ -z "$AWS_ACCOUNT_ID" ]; then
  echo "AWS_ACCOUNT_ID is required (12-digit account ID)." >&2
  exit 1
fi
if [ -z "$TASK_ROLE_ARN" ] || [ -z "$EXECUTION_ROLE_ARN" ]; then
  echo "TASK_ROLE_ARN and EXECUTION_ROLE_ARN are required for Fargate task definitions." >&2
  exit 1
fi

command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required for deployment." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required for deployment." >&2; exit 1; }

ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
LOGS_GROUP="/ecs/${TASK_FAMILY}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASK_DEF_FILE="$(mktemp)"

echo "Authenticating Docker to Amazon ECR..."
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "Building and pushing AuthMap backend image..."
docker build -t "${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}" "$SCRIPT_DIR"
docker push "${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

cat > "$TASK_DEF_FILE" <<EOF
{
  "family": "${TASK_FAMILY}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": [
    "FARGATE"
  ],
  "cpu": "${TASK_CPU}",
  "memory": "${TASK_MEMORY}",
  "taskRoleArn": "${TASK_ROLE_ARN}",
  "executionRoleArn": "${EXECUTION_ROLE_ARN}",
  "containerDefinitions": [
    {
      "name": "authmap-backend",
      "image": "${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}",
      "portMappings": [
        {
          "containerPort": ${CONTAINER_PORT},
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "AUTHMAP_SECURITY_ENABLED",
          "value": "${SECURITY_ENABLED}"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${LOGS_GROUP}",
          "awslogs-region": "${AWS_REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
EOF

echo "Registering ECS task definition..."
TASK_DEF_ARN="$(aws ecs register-task-definition --region "$AWS_REGION" --cli-input-json "file://${TASK_DEF_FILE}" --query 'taskDefinition.taskDefinitionArn' --output text)"
rm -f "$TASK_DEF_FILE"

echo "Updating ECS service ${ECS_CLUSTER}/${ECS_SERVICE}..."
aws ecs update-service \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --service "$ECS_SERVICE" \
  --task-definition "$TASK_DEF_ARN" \
  --force-new-deployment

echo "AuthMap backend deployed to AWS ECS Fargate (${TASK_CPU} CPU units, ${TASK_MEMORY} MB memory)."
