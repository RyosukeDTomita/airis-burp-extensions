#!/bin/bash

echo "Creating Burp Suite AI Extension JAR..."
echo "======================================="

# Create build directory
mkdir -p build

# Copy compiled classes
echo "Copying compiled classes..."
cp -r src/main/java/com/airis/burp/ai/*.class build/ 2>/dev/null || true
mkdir -p build/com/airis/burp/ai/config
cp -r src/main/java/com/airis/burp/ai/config/*.class build/com/airis/burp/ai/config/ 2>/dev/null || true
mkdir -p build/com/airis/burp/ai/core  
cp -r src/main/java/com/airis/burp/ai/core/*.class build/com/airis/burp/ai/core/ 2>/dev/null || true
mkdir -p build/com/airis/burp/ai/llm
cp -r src/main/java/com/airis/burp/ai/llm/*.class build/com/airis/burp/ai/llm/ 2>/dev/null || true
mkdir -p build/com/airis/burp/ai/ui
mkdir -p build/com/airis/burp/ai/utils

# If no compiled classes exist, compile them first
if [ ! -f "src/main/java/com/airis/burp/ai/BurpExtender.class" ]; then
    echo "Compiling Java files..."
    javac -source 8 -target 8 -cp src/main/java src/main/java/com/airis/burp/ai/**/*.java
fi

# Copy classes to build directory  
echo "Organizing classes for JAR..."
cd src/main/java
find . -name "*.class" -exec cp --parents {} ../../../build/ \;
cd ../../..

# Create manifest
echo "Creating manifest..."
mkdir -p build/META-INF
cat > build/META-INF/MANIFEST.MF << EOF
Manifest-Version: 1.0
Main-Class: com.airis.burp.ai.BurpExtender
Implementation-Title: AI Security Analyzer
Implementation-Version: 1.0.0
Implementation-Vendor: AIRIS
EOF

# Create JAR file
echo "Creating JAR file..."
cd build
jar -cfm ../burp-ai-extension.jar META-INF/MANIFEST.MF com/
cd ..

# Cleanup
rm -rf build

echo "JAR file created: burp-ai-extension.jar"
echo "======================================="
echo "Installation instructions:"
echo "1. Open Burp Suite"
echo "2. Go to Extensions tab"
echo "3. Click 'Add'"
echo "4. Select 'Java' as extension type"
echo "5. Choose the burp-ai-extension.jar file"
echo "6. Click 'Next' to load the extension"
echo ""
echo "Note: You'll need to configure the LLM API settings in the extension tab after installation."