package com.airis.burp.ai.core;

import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import java.util.HashMap;
import java.util.Map;

public class AnalysisEngineTest {
    private AnalysisEngine analysisEngine;
    private ConfigManager configManager;

    public static void main(String[] args) {
        AnalysisEngineTest test = new AnalysisEngineTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testInitialization();
        testAnalyzeRequest();
        testAnalyzeWithInvalidConfig();
        testAnalyzeWithEmptyRequest();
        testSetConfiguration();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        configManager = new ConfigManager("test_analysis_config.json");
        analysisEngine = new AnalysisEngine(configManager);
    }

    private void testInitialization() {
        setUp();
        assertNotNull(analysisEngine);
        assertNotNull(analysisEngine.getConfigManager());
        System.out.println("✓ testInitialization");
    }

    private void testAnalyzeRequest() {
        setUp();
        
        // Setup valid configuration
        ConfigModel config = new ConfigModel();
        config.setProvider("openai");
        config.setEndpoint("https://api.openai.com/v1/chat/completions");
        config.setEncryptedApiKey("encrypted-key");
        config.setSystemPrompt("Analyze for security issues");
        configManager.saveConfig(config);

        // Create test request
        AnalysisRequest request = createTestRequest();
        
        // Mock the LLM client to avoid actual API calls
        analysisEngine.setLLMClient(new MockLLMClient());
        
        AnalysisResponse response = analysisEngine.analyzeRequest(request);
        
        assertNotNull(response);
        assertNotEquals("", response.getAnalysis());
        assertTrue(response.getResponseTime() >= 0);
        System.out.println("✓ testAnalyzeRequest");
    }

    private void testAnalyzeWithInvalidConfig() {
        setUp();
        
        // Don't save any config (invalid state)
        AnalysisRequest request = createTestRequest();
        
        AnalysisResponse response = analysisEngine.analyzeRequest(request);
        
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
        System.out.println("✓ testAnalyzeWithInvalidConfig");
    }

    private void testAnalyzeWithEmptyRequest() {
        setUp();
        
        // Setup valid configuration
        ConfigModel config = new ConfigModel();
        config.setProvider("openai");
        config.setEndpoint("https://api.openai.com/v1/chat/completions");
        config.setEncryptedApiKey("encrypted-key");
        config.setSystemPrompt("Analyze for security issues");
        configManager.saveConfig(config);

        AnalysisResponse response = analysisEngine.analyzeRequest(null);
        
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
        System.out.println("✓ testAnalyzeWithEmptyRequest");
    }

    private void testSetConfiguration() {
        setUp();
        
        ConfigModel config = new ConfigModel();
        config.setProvider("anthropic");
        config.setEndpoint("https://api.anthropic.com/v1/messages");
        config.setEncryptedApiKey("encrypted-anthropic-key");
        config.setSystemPrompt("Custom analysis prompt");
        
        analysisEngine.setConfiguration(config);
        
        // Verify configuration was saved
        ConfigModel savedConfig = configManager.loadConfig();
        assertEquals("anthropic", savedConfig.getProvider());
        assertEquals("https://api.anthropic.com/v1/messages", savedConfig.getEndpoint());
        assertEquals("encrypted-anthropic-key", savedConfig.getEncryptedApiKey());
        assertEquals("Custom analysis prompt", savedConfig.getSystemPrompt());
        System.out.println("✓ testSetConfiguration");
    }

    private AnalysisRequest createTestRequest() {
        AnalysisRequest request = new AnalysisRequest();
        request.setMethod("GET");
        request.setUrl("https://api.example.com/users/123");
        
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer token");
        request.setHeaders(headers);
        
        request.setStatusCode(200);
        request.setResponseBody("{\"id\": 123, \"name\": \"John\"}");
        
        return request;
    }

    // Mock LLM client for testing
    private class MockLLMClient implements LLMClient {
        private String endpoint = "";
        private String apiKey = "";
        private int timeout = 30000;

        public AnalysisResponse analyze(AnalysisRequest request, String systemPrompt) {
            AnalysisResponse response = new AnalysisResponse();
            response.setAnalysis("Mock analysis: Request exposes user ID in URL path");
            response.setResponseTime(100);
            return response;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getApiKey() {
            return apiKey;
        }

        public void setTimeout(int timeoutMs) {
            this.timeout = timeoutMs;
        }

        public int getTimeout() {
            return timeout;
        }
    }

    // Simple assertions
    private void assertEquals(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected: " + expected + ", but was: " + actual);
        }
    }

    private void assertNotNull(Object obj) {
        if (obj == null) {
            throw new AssertionError("Expected non-null value");
        }
    }

    private void assertNotEquals(String expected, String actual) {
        if (expected.equals(actual)) {
            throw new AssertionError("Expected different values, but both were: " + expected);
        }
    }

    private void assertTrue(boolean condition) {
        if (!condition) {
            throw new AssertionError("Expected true, but was false");
        }
    }
}