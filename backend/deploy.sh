#!/usr/bin/env bash

# AuthMap Backend - AWS Lambda (container image) deployment
#
# The backend runs as a container-image Lambda behind a public Function URL:
# no API Gateway, ALB, or always-on compute, so idle cost is effectively zero.
# Long scans are dispatched asynchronously (InvocationType=Event) and report
# progress through Postgres-backed /scan/status polling.
#
# Security guardrails ON by default: AUTHMAP_SECURITY_ENABLED=true (see Dockerfile.lambda).
#
# Required environment:
#   AWS_ACCOUNT_ID    12-digit AWS account ID
#   LAMBDA_ROLE_ARN   IAM role for the function (ECR pull, CloudWatch logs, self-invoke)
#   ENV_FILE          JSON file in Lambda's shape: {"Variables": {"KEY": "value", ...}}
#
# Optional overrides:
#   AWS_REGION, FUNCTION_NAME, ECR_REPOSITORY, IMAGE_TAG, DOCKERFILE,
#   MEMORY_SIZE, TIMEOUT_SECONDS, EPHEMERAL_STORAGE_MB

set -euo pipefail

AWS_REGION="${AWS_REGION:-ap-south-1}"
FUNCTION_NAME="${FUNCTION_NAME:-authmap-backend}"
ECR_REPOSITORY="${ECR_REPOSITORY:-authmap-backend}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
MEMORY_SIZE="${MEMORY_SIZE:-2048}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-900}"
EPHEMERAL_STORAGE_MB="${EPHEMERAL_STORAGE_MB:-1024}"
LAMBDA_ROLE_ARN="${LAMBDA_ROLE_ARN:-}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
ENV_FILE="${ENV_FILE:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="${DOCKERFILE:-${SCRIPT_DIR}/Dockerfile.lambda}"

if [ -z "$AWS_ACCOUNT_ID" ]; then
  echo "AWS_ACCOUNT_ID is required (12-digit account ID)." >&2
  exit 1
fi
if [ -z "$LAMBDA_ROLE_ARN" ]; then
  echo "LAMBDA_ROLE_ARN is required (IAM role assumed by the Lambda function)." >&2
  exit 1
fi
if [ -z "$ENV_FILE" ] || [ ! -f "$ENV_FILE" ]; then
  echo "ENV_FILE is required and must point to a Lambda environment JSON file." >&2
  exit 1
fi

command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required for deployment." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required for deployment." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to validate the environment file." >&2; exit 1; }
docker buildx version >/dev/null 2>&1 || {
  echo "Docker buildx is required (Lambda rejects images with provenance/SBOM attestation manifests)." >&2
  exit 1
}

ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_URI="${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

# Lambda reserves these keys; the runtime sets them and rejects user overrides.
ENV_TMP="$(mktemp)"
trap 'rm -f "$ENV_TMP"' EXIT

echo "Validating environment file and stripping Lambda-reserved keys..."
python3 - "$ENV_FILE" "$ENV_TMP" <<'PY'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src) as handle:
    payload = json.load(handle)

variables = payload.get("Variables", payload)
reserved = {
    "_HANDLER",
    "_X_AMZN_TRACE_ID",
    "AWS_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_DEFAULT_REGION",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "AWS_LAMBDA_INITIALIZATION_TYPE",
    "AWS_LAMBDA_LOG_GROUP_NAME",
    "AWS_LAMBDA_LOG_STREAM_NAME",
    "AWS_LAMBDA_RUNTIME_API",
    "AWS_REGION",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "LAMBDA_RUNTIME_DIR",
    "LAMBDA_TASK_ROOT",
}
stripped = sorted(set(variables) & reserved)
for key in stripped:
    variables.pop(key)
if stripped:
    print(f"  removed reserved keys: {', '.join(stripped)}")

with open(dst, "w") as handle:
    json.dump({"Variables": variables}, handle)
PY

echo "Authenticating Docker to Amazon ECR..."
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "Building and pushing ${IMAGE_URI}..."
# --provenance=false --sbom=false: Lambda only accepts a single-platform image
# manifest and rejects buildx attestation manifests.
docker buildx build \
  --platform linux/amd64 \
  --provenance=false \
  --sbom=false \
  -f "$DOCKERFILE" \
  -t "$IMAGE_URI" \
  "$SCRIPT_DIR" \
  --push

if aws lambda get-function --region "$AWS_REGION" --function-name "$FUNCTION_NAME" >/dev/null 2>&1; then
  echo "Updating existing Lambda function ${FUNCTION_NAME}..."
  aws lambda update-function-code \
    --region "$AWS_REGION" \
    --function-name "$FUNCTION_NAME" \
    --image-uri "$IMAGE_URI" \
    --publish >/dev/null
  aws lambda wait function-updated-v2 --region "$AWS_REGION" --function-name "$FUNCTION_NAME"

  aws lambda update-function-configuration \
    --region "$AWS_REGION" \
    --function-name "$FUNCTION_NAME" \
    --role "$LAMBDA_ROLE_ARN" \
    --memory-size "$MEMORY_SIZE" \
    --timeout "$TIMEOUT_SECONDS" \
    --ephemeral-storage "Size=${EPHEMERAL_STORAGE_MB}" \
    --environment "file://${ENV_TMP}" >/dev/null
  aws lambda wait function-updated-v2 --region "$AWS_REGION" --function-name "$FUNCTION_NAME"
else
  echo "Creating Lambda function ${FUNCTION_NAME}..."
  aws lambda create-function \
    --region "$AWS_REGION" \
    --function-name "$FUNCTION_NAME" \
    --package-type Image \
    --code "ImageUri=${IMAGE_URI}" \
    --role "$LAMBDA_ROLE_ARN" \
    --architectures x86_64 \
    --memory-size "$MEMORY_SIZE" \
    --timeout "$TIMEOUT_SECONDS" \
    --ephemeral-storage "Size=${EPHEMERAL_STORAGE_MB}" \
    --environment "file://${ENV_TMP}" >/dev/null
  aws lambda wait function-active-v2 --region "$AWS_REGION" --function-name "$FUNCTION_NAME"
fi

if ! aws lambda get-function-url-config --region "$AWS_REGION" --function-name "$FUNCTION_NAME" >/dev/null 2>&1; then
  echo "Creating public Function URL..."
  aws lambda create-function-url-config \
    --region "$AWS_REGION" \
    --function-name "$FUNCTION_NAME" \
    --auth-type NONE >/dev/null
fi

# A public Function URL needs both permissions; re-running the deploy is safe.
ensure_permission() {
  local statement_id="$1"
  shift
  local output
  if ! output="$(aws lambda add-permission \
      --region "$AWS_REGION" \
      --function-name "$FUNCTION_NAME" \
      --statement-id "$statement_id" \
      "$@" 2>&1)"; then
    if [[ "$output" == *"ResourceConflictException"* ]]; then
      echo "  permission ${statement_id} already exists."
    else
      echo "$output" >&2
      return 1
    fi
  fi
}

ensure_permission FunctionURLAllowPublicAccess \
  --action lambda:InvokeFunctionUrl \
  --principal '*' \
  --function-url-auth-type NONE
ensure_permission FunctionURLAllowPublicInvoke \
  --action lambda:InvokeFunction \
  --principal '*'

FUNCTION_URL="$(aws lambda get-function-url-config --region "$AWS_REGION" --function-name "$FUNCTION_NAME" --query FunctionUrl --output text)"

echo
echo "AuthMap backend deployed to AWS Lambda (${MEMORY_SIZE} MB, ${TIMEOUT_SECONDS}s timeout)."
echo "Function URL: ${FUNCTION_URL}"
echo "Set the frontend to: NEXT_PUBLIC_BACKEND_URL=${FUNCTION_URL%/}"
