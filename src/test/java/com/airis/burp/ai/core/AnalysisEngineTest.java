package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class AnalysisEngineTest {
  private AnalysisEngine analysisEngine;
  private ConfigModel configModel;
  private RequestProcessor requestProcessor;

  @Mock private Logging mockLogging;

  @Mock private LLMClient mockLLMClient;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    ConfigModel.resetInstance();
    configModel = ConfigModel.getInstance();
    requestProcessor = new RequestProcessor(mockLLMClient);
    analysisEngine = new AnalysisEngine(requestProcessor, configModel, mockLogging);
  }

  @AfterEach
  public void tearDown() {
    ConfigModel.resetInstance();
  }

  @Test
  public void testAnalyzeRequestWithValidConfig() {
    // Setup valid configuration
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("test-api-key");
    configModel.setUserPrompt("Analyze for security issues");

    String request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    String response = "HTTP/1.1 200 OK\r\n\r\nTest response";

    // Since we don't have a real API, it will fail, but we can verify the attempt
    String result = analysisEngine.analyzeRequest(request, response);
    assertNotNull(result);

    // Verify logging was called
    verify(mockLogging).logToOutput("Starting AI analysis...");
  }

  @Test
  public void testAnalyzeRequestWithInvalidConfig() {
    // Config is invalid (missing required fields)
    String request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    String response = "HTTP/1.1 200 OK\r\n\r\nTest response";

    String result = analysisEngine.analyzeRequest(request, response);

    assertEquals("Configuration is incomplete. Please configure API settings.", result);
  }

  @Test
  public void testAnalyzeRequestWithNullResponse() {
    // Setup valid configuration
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("test-api-key");
    configModel.setUserPrompt("Analyze for security issues");

    String request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // Should handle null response gracefully
    String result = analysisEngine.analyzeRequest(request, null);
    assertNotNull(result);
  }

  @Test
  public void testIsAnalyzing() {
    assertFalse(analysisEngine.isAnalyzing());

    // Note: We can't easily test the true state without mocking the AI client
    // as the analysis would complete immediately with an error
  }

  @Test
  public void testGetConfigModel() {
    assertSame(configModel, analysisEngine.getConfigModel());
  }

  @Test
  public void testGetLogging() {
    assertSame(mockLogging, analysisEngine.getLogging());
  }

  @Test
  public void testGetRequestProcessor() {
    assertSame(requestProcessor, analysisEngine.getRequestProcessor());
  }

  @Test
  public void testAnalyzeRequestWithDifferentProviders() {
    configModel.setEndpoint("https://api.example.com");
    configModel.setApiKey("test-key");
    configModel.setUserPrompt("Test prompt");

    // Test with OpenAI provider
    configModel.setProvider("openai");
    String result1 = analysisEngine.analyzeRequest("test", "test");
    assertNotNull(result1);

    // Test with Anthropic provider
    configModel.setProvider("anthropic");
    String result2 = analysisEngine.analyzeRequest("test", "test");
    assertNotNull(result2);

    // Test with Gemini provider
    configModel.setProvider("gemini");
    String result3 = analysisEngine.analyzeRequest("test", "test");
    assertNotNull(result3);

    // Test with unknown provider
    configModel.setProvider("unknown");
    String result4 = analysisEngine.analyzeRequest("test", "test");
    assertTrue(result4.contains("Unsupported AI provider"));
  }
}
