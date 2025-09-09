package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ConfigModelTest {
  private ConfigModel configModel;

  @BeforeEach
  public void setUp() {
    configModel = new ConfigModel();
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
}
