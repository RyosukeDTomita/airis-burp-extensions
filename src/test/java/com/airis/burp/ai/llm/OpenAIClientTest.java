package com.airis.burp.ai.llm;

import com.airis.burp.ai.core.AnalysisRequest;
import com.airis.burp.ai.core.AnalysisResponse;
import java.util.HashMap;
import java.util.Map;

public class OpenAIClientTest {
    private OpenAIClient openAIClient;

    public static void main(String[] args) {
        OpenAIClientTest test = new OpenAIClientTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testInitialization();
        testFormatRequest();
        testParseResponse();
        testAnalyzeWithMockResponse();
        testErrorHandling();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        openAIClient = new OpenAIClient();
        openAIClient.setEndpoint("https://api.openai.com/v1/chat/completions");
        openAIClient.setApiKey("test-key");
    }

    private void testInitialization() {
        setUp();
        assertEquals("https://api.openai.com/v1/chat/completions", openAIClient.getEndpoint());
        assertEquals("test-key", openAIClient.getApiKey());
        assertEquals(30000, openAIClient.getTimeout()); // Default timeout
        System.out.println("✓ testInitialization");
    }

    private void testFormatRequest() {
        setUp();
        AnalysisRequest request = createTestRequest();
        String systemPrompt = "Analyze for security issues";
        
        String jsonRequest = openAIClient.formatRequest(request, systemPrompt);
        
        assertNotNull(jsonRequest);
        assertNotEquals("", jsonRequest);
        assertTrue(jsonRequest.contains("gpt-3.5-turbo"));
        assertTrue(jsonRequest.contains(systemPrompt));
        assertTrue(jsonRequest.contains(request.getMethod()));
        assertTrue(jsonRequest.contains(request.getUrl()));
        System.out.println("✓ testFormatRequest");
    }

    private void testParseResponse() {
        setUp();
        String mockResponse = "{\n" +
            "  \"choices\": [{\n" +
            "    \"message\": {\n" +
            "      \"content\": \"Analysis: This request exposes user ID in URL path\"\n" +
            "    }\n" +
            "  }]\n" +
            "}";
        
        AnalysisResponse response = openAIClient.parseResponse(mockResponse);
        
        assertNotNull(response);
        assertEquals("Analysis: This request exposes user ID in URL path", response.getAnalysis());
        System.out.println("✓ testParseResponse");
    }

    private void testAnalyzeWithMockResponse() {
        setUp();
        // Since we can't make real API calls in tests, we test the mock functionality
        OpenAIClient mockClient = new TestableOpenAIClient();
        mockClient.setEndpoint("https://api.openai.com/v1/chat/completions");
        mockClient.setApiKey("test-key");
        
        AnalysisRequest request = createTestRequest();
        String systemPrompt = "Analyze for security issues";
        
        AnalysisResponse response = mockClient.analyze(request, systemPrompt);
        
        assertNotNull(response);
        assertNotEquals("", response.getAnalysis());
        assertTrue(response.getResponseTime() >= 0);
        System.out.println("✓ testAnalyzeWithMockResponse");
    }

    private void testErrorHandling() {
        setUp();
        
        // Test with null request
        AnalysisResponse response = openAIClient.analyze(null, "prompt");
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
        
        // Test with empty prompt
        AnalysisRequest request = createTestRequest();
        response = openAIClient.analyze(request, "");
        assertNotNull(response);
        assertEquals("", response.getAnalysis());
        
        // Test parsing invalid JSON
        AnalysisResponse parsedResponse = openAIClient.parseResponse("invalid json");
        assertNotNull(parsedResponse);
        assertEquals("", parsedResponse.getAnalysis());
        
        System.out.println("✓ testErrorHandling");
    }

    private AnalysisRequest createTestRequest() {
        AnalysisRequest request = new AnalysisRequest();
        request.setMethod("GET");
        request.setUrl("https://api.example.com/users/123");
        
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer token");
        headers.put("Content-Type", "application/json");
        request.setHeaders(headers);
        
        request.setBody("");
        request.setStatusCode(200);
        request.setResponseBody("{\"id\": 123, \"name\": \"John\", \"email\": \"john@example.com\"}");
        
        return request;
    }

    // Testable version that doesn't make real API calls
    private class TestableOpenAIClient extends OpenAIClient {
        protected String makeHttpRequest(String jsonRequest) {
            // Return a mock response instead of making real HTTP request
            return "{\n" +
                "  \"choices\": [{\n" +
                "    \"message\": {\n" +
                "      \"content\": \"Mock analysis: The request exposes user ID 123 in the URL path, which could lead to enumeration attacks. Consider using UUIDs or implementing proper authorization checks.\"\n" +
                "    }\n" +
                "  }]\n" +
                "}";
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