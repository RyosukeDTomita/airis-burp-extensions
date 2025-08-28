#!/bin/bash

echo "Creating Burp Suite AI Extension JAR with proper API..."
echo "====================================================="

# Clean and compile all Java files
echo "Cleaning and compiling Java files..."
find src/main/java -name "*.class" -delete

javac -source 8 -target 8 -cp src/main/java \
    src/main/java/burp/*.java \
    src/main/java/com/airis/burp/ai/**/*.java

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

# Create build directory
mkdir -p build

# Copy all compiled classes
echo "Copying compiled classes..."
cd src/main/java
find . -name "*.class" -exec cp --parents {} ../../../build/ \;
cd ../../..

# Create manifest
echo "Creating manifest..."
mkdir -p build/META-INF
cat > build/META-INF/MANIFEST.MF << 'EOF'
Manifest-Version: 1.0
Implementation-Title: AI Security Analyzer
Implementation-Version: 1.0.0
Implementation-Vendor: AIRIS

EOF

# Create JAR file
echo "Creating JAR file..."
cd build
jar -cfm ../burp-ai-extension.jar META-INF/MANIFEST.MF .
cd ..

# Cleanup
rm -rf build

echo "JAR file created: burp-ai-extension.jar"
echo "====================================================="

# Verify JAR contents
echo "JAR contents:"
jar -tf burp-ai-extension.jar | head -15

echo ""
echo "Installation instructions:"
echo "1. Open Burp Suite"
echo "2. Go to Extensions tab"  
echo "3. Click 'Add'"
echo "4. Select 'Java' as extension type"
echo "5. Choose the burp-ai-extension.jar file"
echo "6. Click 'Next' to load the extension"
echo ""
echo "After installation:"
echo "- Look for the 'AI Security Analyzer' tab"
echo "- Configure your LLM API settings"
echo "- Use the 'Analyze with AI' functionality in Repeater"