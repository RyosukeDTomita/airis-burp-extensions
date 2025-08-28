#!/bin/bash

echo "Running all tests..."
echo "==================="

# Compile all source files
echo "Compiling all Java files..."
javac -source 8 -target 8 -cp src/main/java:src/test/java src/main/java/com/airis/burp/ai/**/*.java src/test/java/com/airis/burp/ai/**/*.java

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Running individual component tests..."
echo

echo "1. ConfigModel tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.config.ConfigModelTest
echo

echo "2. SecureStorage tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.config.SecureStorageTest
echo

echo "3. ConfigManager tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.config.ConfigManagerTest
echo

echo "4. LLMClient tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.llm.LLMClientTest
echo

echo "5. OpenAIClient tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.llm.OpenAIClientTest
echo

echo "6. BurpExtender tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.BurpExtenderTest
echo

echo "7. RequestProcessor tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.core.RequestProcessorTest
echo

echo "8. AnalysisEngine tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.core.AnalysisEngineTest
echo

echo "9. Integration tests:"
java -cp src/main/java:src/test/java com.airis.burp.ai.IntegrationTest
echo

echo "ALL TESTS COMPLETED!"
echo "==================="