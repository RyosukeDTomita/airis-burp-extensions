#!/bin/bash
curl -H "x-goog-api-key: ${GEMINI_API_KEY}" \
     "https://generativelanguage.googleapis.com/v1beta/models"


MODEL_NAME="gemini-2.5-pro"
ENDPOINT="https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent"

# リクエストボディ
read -r -d '' PAYLOAD << EOF
{
  "contents": [
    {
      "parts": [
        { "text": "これは Gemini 2.5 Flash-Lite API の動作確認テストです。返事をしてください。" }
      ]
    }
  ],
  "generationConfig": {
    "temperature": 0.7,
    "topP": 0.9,
    "topK": 40
  }
}
EOF

# curl 実行
curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "x-goog-api-key: $GEMINI_API_KEY" \
  -d "$PAYLOAD" | jq .
