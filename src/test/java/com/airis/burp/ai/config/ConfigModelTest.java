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
    if (configModel != null) {
      configModel = null;
    }
  }

  @Test
  public void shouldThrowUnsupportedOperationExceptionForDefaultConstructor() {
    assertThrows(
        UnsupportedOperationException.class,
        () -> {
          new ConfigModel();
        });
  }

  @Test
  public void shouldReturnInstanceInfoWhenToString() {
    configModel =
        new ConfigModel(
            "openai", "https://api.openai.com/v1/chat/completions", "sk-xxxxxxxxxxtest");

    String result = configModel.toString();

    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, apiKey=***test)",
        result);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "a", "ab", "abc",
      })
  public void shouldReturnInstanceInfo2WhenToString(String apiKey) {
    configModel = new ConfigModel("openai", "https://api.openai.com/v1/chat/completions", apiKey);

    String result = configModel.toString();

    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, apiKey=***)",
        result);
  }

  @ParameterizedTest
  @ValueSource(strings = {"openai", "anthropic"})
  public void shouldConstructSuccessfullyForValidProviders(String provider) {
    assertDoesNotThrow(
        () -> {
          configModel =
              new ConfigModel(provider, "https://api.example.com/v1/endpoint", "test-api-key");
        });
  }

  @Test
  public void shouldThrowExceptionForInvalidProvider() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new ConfigModel(
              "invalid_provider", "https://api.example.com/v1/chat", "sk-xxxxxxxxxxxxxxxxxtest");
        });
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "http://api.example.com/invalid", "api.example.com/invalid"})
  public void shouldThrowExceptionForInvalidEndpoint(String endpoint) {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new ConfigModel("openai", endpoint, "sk-xxxxxxxxxxxxxxxxxtest");
        });
  }

  @Test
  public void shouldThrowExceptionForEmptyApiKey() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new ConfigModel("openai", "https://api.example.com/v1/chat", "");
        });
  }

  @Test
  public void shouldThrowExceptionForEmptyUserPrompt() {
    // This test is no longer relevant since userPrompt was removed
    // Testing that we can create ConfigModel without userPrompt
    assertDoesNotThrow(
        () -> {
          new ConfigModel("openai", "https://api.example.com/v1/chat", "sk-xxxxxxxxxxxxxxxxxtest");
        });
  }

  @Test
  public void getApiKeyshouldReturnApiKey() {
    configModel =
        new ConfigModel(
            "openai", "https://api.openai.com/v1/chat/completions", "sk-xxxxxxxxxxxtest");

    assertEquals("sk-xxxxxxxxxxxtest", configModel.getApiKey());
  }

  @Test
  public void getApiKeyshouldReturnApiKeyAsString() {
    configModel =
        new ConfigModel(
            "openai", "https://api.openai.com/v1/chat/completions", "sk-xxxxxxxxxxxtest");

    assertEquals("sk-xxxxxxxxxxxtest", configModel.getApiKey());
  }
}
