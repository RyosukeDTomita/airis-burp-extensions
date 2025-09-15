package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ConfigModelTest {
  private ConfigModel configModel;

  @BeforeEach
  public void setUp() {
    configModel = new ConfigModel();
  }

  @AfterEach
  public void tearDown() {
    configModel = null;
  }

  @Test
  public void toString_should_return_instance_info() {
    // Arrange
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("sk-proj-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    // Act
    String result = configModel.toString();

    // Assert
    assertNotNull(result);
    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, apiKey=***test, userPrompt=Analyze the request for vulnerabilities.)",
        result);
  }

  @Test
  public void copyConstructor_ShouldCreateCopy() {
    // Arrange
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("sk-proj-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    // Act
    ConfigModel copyInstance = new ConfigModel(configModel);

    // Assert
    assertEquals(copyInstance, configModel);
  }
}
