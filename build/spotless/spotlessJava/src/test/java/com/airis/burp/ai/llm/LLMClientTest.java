package com.airis.burp.ai.llm;

import static org.junit.jupiter.api.Assertions.*;

import com.airis.burp.ai.core.AnalysisResult;
import com.airis.burp.ai.core.AnalysisTarget;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class LLMClientTest {
  private MockLLMClient llmClient;

  @BeforeEach
  public void setUp() {
    llmClient = new MockLLMClient();
  }

  @Test
  public void testAnalyzeRequest() {
    AnalysisTarget request = new AnalysisTarget();
    request.setMethod("GET");
    request.setUrl("https://example.com/api/users/123");
    request.setHeaders(createHeaders());
    request.setBody("");
    request.setStatusCode(200);
    request.setResponseBody("{\"id\": 123, \"name\": \"test\"}");

    String userPrompt = "Analyze this HTTP request for security issues";

    AnalysisResult response = llmClient.analyze(request, userPrompt);

    assertNotNull(response);
    assertNotEquals("", response.getAnalysis());
    assertTrue(response.getResponseTime() > 0);
  }

  @Test
  public void testInvalidInput() {
    // Test null request
    AnalysisResult response = llmClient.analyze(null, "prompt");
    assertNotNull(response);
    assertEquals("", response.getAnalysis());

    // Test empty prompt
    AnalysisTarget request = new AnalysisTarget();
    response = llmClient.analyze(request, "");
    assertNotNull(response);
    assertEquals("", response.getAnalysis());
  }

  @Test
  public void testTimeout() {
    llmClient.setTimeout(1000); // 1 second
    assertEquals(1000, llmClient.getTimeout());

    llmClient.setTimeout(30000); // 30 seconds
    assertEquals(30000, llmClient.getTimeout());
  }

  @Test
  public void testConnectionSettings() {
    String endpoint = "https://api.openai.com/v1/chat/completions";
    String apiKey = "test-api-key";

    llmClient.setEndpoint(endpoint);
    llmClient.setApiKey(apiKey);

    assertEquals(endpoint, llmClient.getEndpoint());
    assertEquals(apiKey, llmClient.getApiKey());
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

    public AnalysisResult analyze(AnalysisTarget request, String userPrompt) {
      if (request == null || userPrompt == null || userPrompt.isEmpty()) {
        AnalysisResult response = new AnalysisResult();
        response.setAnalysis("");
        response.setResponseTime(0);
        return response;
      }

      AnalysisResult response = new AnalysisResult();
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
}
