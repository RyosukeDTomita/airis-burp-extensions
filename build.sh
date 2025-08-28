#!/bin/bash

echo "🚀 Building AIRIS..."

# Build and extract JAR in one command
docker build -t airis-builder . --target builder
CONTAINER_ID=$(docker create airis-builder)
docker rm $CONTAINER_ID && \
docker rmi airis-builder && \
echo "✅ Success! airis-burp.jar created"
