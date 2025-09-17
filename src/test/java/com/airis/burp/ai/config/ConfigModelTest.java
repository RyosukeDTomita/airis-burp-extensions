package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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
  public void shouldReturnInstanceInfoWhenToString() {
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("sk-proj-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    String result = configModel.toString();

    assertNotNull(result);
    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, apiKey=***test, userPrompt=Analyze the request for vulnerabilities.)",
        result);
  }

  @Test
  public void shouldCreateCopyWithCopyConstructor() {
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
    configModel.setApiKey("sk-proj-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    ConfigModel copyInstance = new ConfigModel(configModel);

    assertEquals(copyInstance, configModel);
  }

  @ParameterizedTest
  @ValueSource(strings = {"openai", "anthropic"})
  public void shouldReturnTrueForValidProviders(String provider) {
    configModel.setProvider(provider);
    configModel.setEndpoint("https://api.example.com/v1/endpoint");
    configModel.setApiKey("test-api-key");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    Boolean isValid = configModel.isValid();

    assertTrue(isValid);
  }

  @Test
  public void shouldReturnFalseForInvalidProvider() {
    configModel.setProvider("invalid_provider");
    configModel.setEndpoint("https://api.example.com/v1/chat");
    configModel.setApiKey("sk-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    Boolean isValid = configModel.isValid();

    assertFalse(isValid);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "http://api.example.com/invalid", "api.example.com/invalid"})
  public void shouldReturnFalseForInvalidEndpoint(String endpoint) {
    configModel.setProvider("openai");
    configModel.setEndpoint(endpoint);
    configModel.setApiKey("sk-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    Boolean isValid = configModel.isValid();

    assertFalse(isValid);
  }

  @Test
  public void shouldReturnFalseForEmptyApiKey() {
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.example.com/v1/chat");
    configModel.setApiKey("");
    configModel.setUserPrompt("Analyze the request for vulnerabilities.");

    Boolean isValid = configModel.isValid();

    assertFalse(isValid);
  }

  @Test
  public void shouldReturnFalseForEmptyUserPrompt() {
    configModel.setProvider("openai");
    configModel.setEndpoint("https://api.example.com/v1/chat");
    configModel.setApiKey("sk-xxxxxxxxxxxxxxxxxtest");
    configModel.setUserPrompt("");

    Boolean isValid = configModel.isValid();

    assertFalse(isValid);
  }
}
