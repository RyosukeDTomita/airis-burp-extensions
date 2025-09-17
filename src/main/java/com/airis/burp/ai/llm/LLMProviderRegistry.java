package com.airis.burp.ai.llm;

/** Registry for available LLM providers. Manages supported providers and their clients. */
public class LLMProviderRegistry {

  /** Enum for supported LLM providers */
  public enum Provider {
    OPENAI,
    ANTHROPIC
  }

  // Provider types (for backward compatibility)
  public static final String PROVIDER_OPENAI = "openai";
  public static final String PROVIDER_ANTHROPIC = "anthropic";

  // Default endpoints for different providers
  public static final String DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";
  public static final String DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages";

  /** Get the default endpoint for a provider */
  public static String getDefaultEndpoint(String provider) {
    switch (provider) {
      case PROVIDER_OPENAI:
        return DEFAULT_OPENAI_ENDPOINT;
      case PROVIDER_ANTHROPIC:
        return DEFAULT_ANTHROPIC_ENDPOINT;
      default:
        throw new IllegalArgumentException("Unsupported provider: " + provider);
    }
  }
}
