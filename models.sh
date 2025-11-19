#!/usr/bin/env bash
set -euo pipefail

: "${OPENAI_API_KEY:?Environment variable OPENAI_API_KEY must be set}"
: "${ANTHROPIC_API_KEY:?Environment variable ANTHROPIC_API_KEY must be set}"
ANTHROPIC_VERSION=${ANTHROPIC_VERSION:-2023-06-01}

echo "==== OpenAI supported models ===="
curl \
  -H "Authorization: Bearer ${OPENAI_API_KEY}" \
  -H "Content-Type: application/json" \
  https://api.openai.com/v1/models

echo
echo "==== Anthropic supported models ===="
curl \
  -H "x-api-key: ${ANTHROPIC_API_KEY}" \
  -H "anthropic-version: ${ANTHROPIC_VERSION}" \
  https://api.anthropic.com/v1/models
