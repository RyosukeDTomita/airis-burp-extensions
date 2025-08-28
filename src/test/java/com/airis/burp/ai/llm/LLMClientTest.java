package com.airis.burp.ai.llm;

import com.airis.burp.ai.core.AnalysisRequest;
import com.airis.burp.ai.core.AnalysisResponse;
import java.util.HashMap;
import java.util.Map;

public class LLMClientTest {
    private MockLLMClient llmClient;

    public static void main(String[] args) {
        LLMClientTest test = new LLMClientTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testAnalyzeRequest();
        testInvalidInput();
        testTimeout();
        testConnectionSettings();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        llmClient = new MockLLMClient();
    }

    private void testAnalyzeRequest() {
        setUp();
        
        AnalysisRequest request = new AnalysisRequest();
        request.setMethod("GET");
        request.setUrl("https://example.com/api/users/123");
        request.setHeaders(createHeaders());
        request.setBody("");
        request.setStatusCode(200);
        request.setResponseBody("{\"id\": 123, \"name\": \"test\"}");
        
        String systemPrompt = "Analyze this HTTP request for security issues";
        
        AnalysisResponse response = llmClient.analyze(request, systemPrompt);
        
        assertNotNull(response);
        assertNotEquals("", response.getAnalysis());
        assertTrue(response.getResponseTime() > 0);
        System.out.println("✓ testAnalyzeRequest");
    }

    private void testInvalidInput() {
        setUp();
        
        // Test null request
        AnalysisResponse response = llmClient.analyze(null, "prompt");
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
        
        // Test empty prompt
        AnalysisRequest request = new AnalysisRequest();
        response = llmClient.analyze(request, "");
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
        
        System.out.println("✓ testInvalidInput");
    }

    private void testTimeout() {
        setUp();
        
        llmClient.setTimeout(1000); // 1 second
        assertEquals(1000, llmClient.getTimeout());
        
        llmClient.setTimeout(30000); // 30 seconds  
        assertEquals(30000, llmClient.getTimeout());
        System.out.println("✓ testTimeout");
    }

    private void testConnectionSettings() {
        setUp();
        
        String endpoint = "https://api.openai.com/v1/chat/completions";
        String apiKey = "test-api-key";
        
        llmClient.setEndpoint(endpoint);
        llmClient.setApiKey(apiKey);
        
        assertEquals(endpoint, llmClient.getEndpoint());
        assertEquals(apiKey, llmClient.getApiKey());
        System.out.println("✓ testConnectionSettings");
    }

    private Map<String, String> createHeaders() {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "Bearer token");
        return headers;
    }

    // Mock implementation for testing
    private class MockLLMClient implements LLMClient {
        private String endpoint = "";
        private String apiKey = "";
        private int timeout = 30000;

        public AnalysisResponse analyze(AnalysisRequest request, String systemPrompt) {
            if (request == null || systemPrompt == null || systemPrompt.isEmpty()) {
                AnalysisResponse response = new AnalysisResponse();
                response.setAnalysis("");
                response.setResponseTime(0);
                return response;
            }
            
            AnalysisResponse response = new AnalysisResponse();
            response.setAnalysis("Mock analysis: The request appears to expose user ID in URL");
            response.setResponseTime(100);
            return response;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint != null ? endpoint : "";
        }

        public String getEndpoint() {
            return endpoint;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey != null ? apiKey : "";
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

    private void assertEquals(int expected, int actual) {
        if (expected != actual) {
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