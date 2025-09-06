package com.airis.burp.ai;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.core.RequestProcessor;
import com.airis.burp.ai.llm.LLMClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class IntegrationTest {
  
  @Mock
  private Logging mockLogging;
  
  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  public void testEndToEndWorkflow() {
    // Create and configure model
    ConfigModel config = new ConfigModel();
    config.setProvider("openai");
    config.setEndpoint("https://api.openai.com/v1/chat/completions");
    config.setApiKey("test-api-key");
    config.setUserPrompt("Analyze this HTTP request for security vulnerabilities");
    
    // Create analysis engine
    LLMClient mockLLMClient = mock(LLMClient.class);
    RequestProcessor processor = new RequestProcessor(mockLLMClient);
    AnalysisEngine engine = new AnalysisEngine(processor, config, mockLogging);
    
    // Create HTTP request/response
    String httpRequest = 
        "POST /api/login HTTP/1.1\r\n" +
        "Host: example.com\r\n" +
        "Content-Type: application/x-www-form-urlencoded\r\n" +
        "\r\n" +
        "username=admin&password=secret123";
    
    String httpResponse = 
        "HTTP/1.1 200 OK\r\n" +
        "Set-Cookie: sessionid=abc123\r\n" +
        "\r\n" +
        "{\"success\": true, \"user_id\": 1}";
    
    // Analyze the traffic
    String result = engine.analyzeRequest(httpRequest, httpResponse);
    assertNotNull(result);
    
    // Verify that proper error message is returned since we don't have real API
    assertTrue(result.contains("Analysis failed") || result.contains("Configuration"));
  }

  @Test
  public void testConfigurationValidation() {
    ConfigModel config = new ConfigModel();
    
    // Initially invalid
    assertFalse(config.isValid());
    
    // Add required fields one by one
    config.setProvider("openai");
    assertFalse(config.isValid());
    
    config.setEndpoint("https://api.openai.com/v1/chat/completions");
    assertFalse(config.isValid());
    
    config.setApiKey("test-key");
    assertFalse(config.isValid());
    
    config.setUserPrompt("Test prompt");
    assertTrue(config.isValid());
  }

  @Test
  public void testDefaultUserPrompt() {
    ConfigModel config = new ConfigModel();
    
    // Should have default prompt
    assertNotNull(config.getUserPrompt());
    assertEquals(ConfigModel.DEFAULT_USER_PROMPT, config.getUserPrompt());
  }

  @Test
  public void testAnalysisEngineWithInvalidConfig() {
    ConfigModel config = new ConfigModel();
    // config is invalid (missing provider, endpoint, apiKey)
    
    LLMClient mockLLMClient = mock(LLMClient.class);
    RequestProcessor processor = new RequestProcessor(mockLLMClient);
    AnalysisEngine engine = new AnalysisEngine(processor, config, mockLogging);
    
    String result = engine.analyzeRequest("test request", "test response");
    
    // Should return error message
    assertTrue(result.contains("Configuration is incomplete"));
  }
}