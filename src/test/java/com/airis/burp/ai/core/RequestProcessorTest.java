package com.airis.burp.ai.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;

public class RequestProcessorTest {
    private RequestProcessor requestProcessor;

    @BeforeEach
    public void setUp() {
        requestProcessor = new RequestProcessor();
    }

    @Test
    public void testParseHttpRequest() {
        String httpRequest = "GET /api/users/123?active=true HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Authorization: Bearer token123\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"query\": \"test\"}";

        AnalysisRequest request = requestProcessor.parseHttpRequest(httpRequest);
        
        assertNotNull(request);
        assertEquals("GET", request.getMethod());
        assertEquals("/api/users/123?active=true", request.getUrl());
        assertNotNull(request.getHeaders());
        assertTrue(request.getHeaders().containsKey("Host"));
        assertEquals("example.com", request.getHeaders().get("Host"));
        assertTrue(request.getHeaders().containsKey("Authorization"));
        assertEquals("Bearer token123", request.getHeaders().get("Authorization"));
        assertEquals("{\"query\": \"test\"}", request.getBody());
    }

    @Test
    public void testParseHttpResponse() {
        String httpResponse = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Set-Cookie: session=abc123\r\n" +
                "\r\n" +
                "{\"id\": 123, \"name\": \"John\"}";

        AnalysisRequest request = new AnalysisRequest();
        requestProcessor.parseHttpResponse(request, httpResponse);
        
        assertEquals(200, request.getStatusCode());
        assertEquals("{\"id\": 123, \"name\": \"John\"}", request.getResponseBody());
    }

    @Test
    public void testCreateAnalysisRequest() {
        String httpRequest = "POST /login HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "\r\n" +
                "username=admin&password=secret";

        String httpResponse = "HTTP/1.1 302 Found\r\n" +
                "Location: /dashboard\r\n" +
                "Set-Cookie: session=xyz789\r\n" +
                "\r\n";

        AnalysisRequest analysisRequest = requestProcessor.createAnalysisRequest(httpRequest, httpResponse);
        
        assertNotNull(analysisRequest);
        assertEquals("POST", analysisRequest.getMethod());
        assertEquals("/login", analysisRequest.getUrl());
        assertEquals(302, analysisRequest.getStatusCode());
        assertEquals("username=admin&password=secret", analysisRequest.getBody());
    }

    @Test
    public void testSanitizeData() {
        // Test password sanitization
        String sensitiveData = "password=secret123&username=admin&api_key=sk-1234567890";
        String sanitized = requestProcessor.sanitizeData(sensitiveData);
        
        assertNotEquals(sensitiveData, sanitized);
        assertFalse(sanitized.contains("secret123"));
        assertFalse(sanitized.contains("sk-1234567890"));
        assertTrue(sanitized.contains("[REDACTED]"));
    }

    @Test
    public void testExtractHeaders() {
        String headerLines = "Host: example.com\r\n" +
                "Authorization: Bearer token123\r\n" +
                "Content-Type: application/json\r\n" +
                "X-Custom-Header: test-value";

        Map<String, String> headers = requestProcessor.extractHeaders(headerLines);
        
        assertNotNull(headers);
        assertEquals(4, headers.size());
        assertEquals("example.com", headers.get("Host"));
        assertEquals("Bearer token123", headers.get("Authorization"));
        assertEquals("application/json", headers.get("Content-Type"));
        assertEquals("test-value", headers.get("X-Custom-Header"));
    }
}