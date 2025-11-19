package com.airis.burp.ai.config;

import static org.junit.jupiter.api.Assertions.*;

import com.airis.burp.ai.llm.LLMProviderRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class ConfigModelTest {

  private static final String OPENAI_ENDPOINT = LLMProviderRegistry.DEFAULT_OPENAI_ENDPOINT;
  private ConfigModel configModel;

  @AfterEach
  public void tearDown() {
    configModel = null;
  }

  @Test
  public void shouldThrowUnsupportedOperationExceptionForDefaultConstructor() {
    assertThrows(UnsupportedOperationException.class, ConfigModel::new);
  }

  @Test
  public void shouldReturnInstanceInfoWhenToString() {
    configModel =
        new ConfigModel(
            LLMProviderRegistry.PROVIDER_OPENAI,
            OPENAI_ENDPOINT,
            LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
            "sk-xxxxxxxxxxtest");

    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, model=gpt-4o-mini, apiKey=***test)",
        configModel.toString());
  }

  @ParameterizedTest
  @ValueSource(strings = {"a", "ab", "abc"})
  public void shouldMaskShortApiKeysInToString(String apiKey) {
    configModel =
        new ConfigModel(
            LLMProviderRegistry.PROVIDER_OPENAI,
            OPENAI_ENDPOINT,
            LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
            apiKey);

    assertEquals(
        "ConfigModel(provider=openai, endpoint=https://api.openai.com/v1/chat/completions, model=gpt-4o-mini, apiKey=***)",
        configModel.toString());
  }

  @ParameterizedTest
  @ValueSource(strings = {LLMProviderRegistry.PROVIDER_OPENAI, LLMProviderRegistry.PROVIDER_ANTHROPIC})
  public void shouldConstructSuccessfullyForValidProviders(String provider) {
    assertDoesNotThrow(
        () ->
            new ConfigModel(
                provider,
                "https://api.example.com/v1/endpoint",
                LLMProviderRegistry.getDefaultModel(provider),
                "test-api-key"));
  }

  @Test
  public void shouldThrowExceptionForInvalidProvider() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ConfigModel(
                "invalid_provider",
                "https://api.example.com/v1/chat",
                LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
                "sk-xxxxxxxxxxxxxxxxxtest"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "http://api.example.com/invalid", "api.example.com/invalid"})
  public void shouldThrowExceptionForInvalidEndpoint(String endpoint) {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ConfigModel(
                LLMProviderRegistry.PROVIDER_OPENAI,
                endpoint,
                LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
                "sk-xxxxxxxxxxxxxxxxxtest"));
  }

  @Test
  public void shouldThrowExceptionForEmptyApiKey() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ConfigModel(
                LLMProviderRegistry.PROVIDER_OPENAI,
                "https://api.example.com/v1/chat",
                LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
        ""));
  }

  @Test
  public void shouldConstructSuccessfullyWithoutPrompt() {
    assertDoesNotThrow(
        () ->
            new ConfigModel(
                LLMProviderRegistry.PROVIDER_OPENAI,
                "https://api.example.com/v1/chat",
                LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
        "sk-xxxxxxxxxxxxxxxxxtest"));
  }

  @Test
  public void getApiKeyShouldReturnApiKey() {
    configModel =
        new ConfigModel(
            LLMProviderRegistry.PROVIDER_OPENAI,
            OPENAI_ENDPOINT,
            LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
            "sk-xxxxxxxxxxxtest");

    assertEquals("sk-xxxxxxxxxxxtest", configModel.getApiKey());
  }

  @Test
  public void getApiKeyShouldReturnApiKeyAsString() {
    configModel =
        new ConfigModel(
            LLMProviderRegistry.PROVIDER_OPENAI,
            OPENAI_ENDPOINT,
            LLMProviderRegistry.DEFAULT_OPENAI_MODEL,
            "sk-xxxxxxxxxxxtest");

    assertEquals("sk-xxxxxxxxxxxtest", configModel.getApiKey());
  }
}
