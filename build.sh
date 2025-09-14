#!/bin/bash

echo "🚀 Building AIRIS..."

# Create build directory if it doesn't exist
mkdir -p ./build

# Build and extract JAR in one command
docker build -t airis-builder . --target builder
CONTAINER_ID=$(docker create airis-builder)
docker cp $CONTAINER_ID:/app/build/libs/airis-burp.jar ./build/
docker rm $CONTAINER_ID
docker rmi airis-builder
echo "✅ Success! airis-burp.jar created in ./build/"
