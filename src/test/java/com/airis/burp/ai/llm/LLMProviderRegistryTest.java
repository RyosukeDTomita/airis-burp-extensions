package com.airis.burp.ai.llm;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class LLMProviderRegistryTest {

  @Test
  public void testGetDefaultEndpointForOpenAI() {
    String endpoint = LLMProviderRegistry.getDefaultEndpoint(LLMProviderRegistry.PROVIDER_OPENAI);
    assertEquals(LLMProviderRegistry.DEFAULT_OPENAI_ENDPOINT, endpoint);
    assertEquals("https://api.openai.com/v1/chat/completions", endpoint);
  }

  @Test
  public void testGetDefaultEndpointForAnthropic() {
    String endpoint =
        LLMProviderRegistry.getDefaultEndpoint(LLMProviderRegistry.PROVIDER_ANTHROPIC);
    assertEquals(LLMProviderRegistry.DEFAULT_ANTHROPIC_ENDPOINT, endpoint);
    assertEquals("https://api.anthropic.com/v1/messages", endpoint);
  }

  @Test
  public void testGetDefaultEndpointForGemini() {
    String endpoint = LLMProviderRegistry.getDefaultEndpoint(LLMProviderRegistry.PROVIDER_GEMINI);
    assertEquals(LLMProviderRegistry.DEFAULT_GEMINI_ENDPOINT, endpoint);
    assertEquals(
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        endpoint);
  }
}
