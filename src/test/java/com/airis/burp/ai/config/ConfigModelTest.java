package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;



public class ConfigModelTest {

  private ConfigModel configModel;

  @AfterEach
  public void tearDown() {
    configModel = null;
  }

  @Test
  public void shouldReturnInstanceInfoWhenToString() {
    configModel = new ConfigModel("openai", "https://api.openai.com/v1/chat/completions",
        "sk-proj-xxxxxxxxxxxxxxxxxtest", "Analyze the request for vulnerabilities.");

    String result = configModel.toString();

    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, apiKey=***test, userPrompt=Analyze the request for vulnerabilities.)",
        result);
  }


  @ParameterizedTest
  @ValueSource(strings = {"openai", "anthropic"})
  public void shouldConstructSuccessfullyForValidProviders(String provider) {
    assertDoesNotThrow(() -> {
      configModel = new ConfigModel(provider, "https://api.example.com/v1/endpoint", "test-api-key",
          "Analyze the request for vulnerabilities.");
    });
  }

  @Test
  public void shouldThrowExceptionForInvalidProvider() {
    assertThrows(IllegalArgumentException.class, () -> {
      new ConfigModel("invalid_provider", "https://api.example.com/v1/chat",
          "sk-xxxxxxxxxxxxxxxxxtest", "Analyze the request for vulnerabilities.");
    });
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "http://api.example.com/invalid", "api.example.com/invalid"})
  public void shouldThrowExceptionForInvalidEndpoint(String endpoint) {
    assertThrows(IllegalArgumentException.class, () -> {
      new ConfigModel("openai", endpoint, "sk-xxxxxxxxxxxxxxxxxtest",
          "Analyze the request for vulnerabilities.");
    });
  }

  @Test
  public void shouldThrowExceptionForEmptyApiKey() {
    assertThrows(IllegalArgumentException.class, () -> {
      new ConfigModel("openai", "https://api.example.com/v1/chat", "",
          "Analyze the request for vulnerabilities.");
    });
  }

  @Test
  public void shouldThrowExceptionForEmptyUserPrompt() {
    assertThrows(IllegalArgumentException.class, () -> {
      new ConfigModel("openai", "https://api.example.com/v1/chat", "sk-xxxxxxxxxxxxxxxxxtest", "");
    });
  }

  @Test
  public void shouldThrowUnsupportedOperationExceptionForDefaultConstructor() {
    assertThrows(UnsupportedOperationException.class, () -> {
      new ConfigModel();
    });
  }
}
