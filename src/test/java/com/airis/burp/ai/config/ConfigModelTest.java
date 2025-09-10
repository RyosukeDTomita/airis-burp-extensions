package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
  public void testSingletonInstance() {
    // Act
    ConfigModel firstInstance = ConfigModel.getInstance();
    ConfigModel secondInstance = ConfigModel.getInstance();

    // Assert
    assertSame(firstInstance, secondInstance);
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
