package com.airis.burp.ai.llm;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class LLMProviderRegistryTest {

  @Test
  public void shouldReturnDefaultEndpointForOpenAI() {
    String provider = "openai";

    String endpoint = LLMProviderRegistry.getDefaultEndpoint(provider);

    assertEquals("https://api.openai.com/v1/chat/completions", endpoint);
  }

  @Test
  public void shouldReturnDefaultEndpointForAnthropic() {
    String provider = "anthropic";

    String endpoint = LLMProviderRegistry.getDefaultEndpoint(provider);

  assertEquals("https://api.anthropic.com/v1/messages", endpoint);
  }
}
