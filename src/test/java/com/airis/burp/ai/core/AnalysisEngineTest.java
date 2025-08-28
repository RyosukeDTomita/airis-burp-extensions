package com.airis.burp.ai.core;

import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.HashMap;
import java.io.File;

public class AnalysisEngineTest {
    private AnalysisEngine analysisEngine;
    private ConfigManager configManager;

    @BeforeEach
    public void setUp() {
        configManager = new ConfigManager("test_analysis_config.json");
        analysisEngine = new AnalysisEngine(configManager);
    }

    @AfterEach
    public void tearDown() {
        // Clean up test config file
        File testFile = new File("test_analysis_config.json");
        if (testFile.exists()) {
            testFile.delete();
        }
    }

    @Test
    public void testInitialization() {
        assertNotNull(analysisEngine);
        assertNotNull(analysisEngine.getConfigManager());
    }

    @Test
    public void testAnalyzeRequest() {
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
    }

    @Test
    public void testAnalyzeWithInvalidConfig() {
        // Don't save any config (invalid state)
        AnalysisRequest request = createTestRequest();
        
        AnalysisResponse response = analysisEngine.analyzeRequest(request);
        
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
    }

    @Test
    public void testAnalyzeWithEmptyRequest() {
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
    }

    @Test
    public void testSetConfiguration() {
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
}