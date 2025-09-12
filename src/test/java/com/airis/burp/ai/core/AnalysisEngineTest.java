package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
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

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    ConfigModel.resetInstance();
    configModel = ConfigModel.getInstance();
    requestProcessor = new RequestProcessor();
    analysisEngine = new AnalysisEngine(requestProcessor, configModel, mockLogging);
  }

  @AfterEach
  public void tearDown() {
    ConfigModel.resetInstance();
  }

  @Test
  public void analyzeIsAlreadyRunning() {
    // Arrange
    // Setup valid configuration
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("test-api-key");
    configModel.setUserPrompt("Analyze for security issues");

    String request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    String response = "HTTP/1.1 200 OK\r\n\r\nTest response";

    // Act
    // Since we don't have a real API, it will fail, but we can verify the attempt
    String result = analysisEngine.analyze(request, response);
  }
}
