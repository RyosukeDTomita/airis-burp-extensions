package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class ConfigModelTest {
  private ConfigModel configModel;

  @BeforeEach
  public void setUp() {
    ConfigModel.resetInstance();
    configModel = ConfigModel.getInstance();
  }

  @AfterEach
  public void tearDown() {
    ConfigModel.resetInstance();
  }

  @Test
  public void testDefaultValues() {
    // Act
    String initialProvider = configModel.getProvider();
    String initialEndpoint = configModel.getEndpoint();
    String initialApiKey = configModel.getApiKey();
    String initialUserPrompt = configModel.getUserPrompt();

    // Assert
    assertEquals("openai", initialProvider);
    assertEquals("", initialEndpoint);
    assertEquals("", initialApiKey);
    assertNotNull(initialUserPrompt);
  }

  @Test
  public void testToString() {
    // Arrange
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("sk-proj-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");
    
    // Act
    String result = configModel.toString();

    // Assert
    assertNotNull(result);
    assertEquals("ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, apiKey=***test, userPrompt=Analyze the request for vulnerabilities.)", result);
  }
}
