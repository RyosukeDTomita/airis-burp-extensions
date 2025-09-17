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

  /** Convert string to Provider enum */
  public static Provider getProviderFromString(String providerName) {
    if (providerName == null) {
      return null;
    }
    switch (providerName.toLowerCase()) {
      case PROVIDER_OPENAI:
        return Provider.OPENAI;
      case PROVIDER_ANTHROPIC:
        return Provider.ANTHROPIC;
      default:
        return null;
    }
  }

  /** Check if the provider name is valid */
  public static boolean isValidProvider(String providerName) {
    return getProviderFromString(providerName) != null;
  }

  /** Get the default endpoint for a provider */
  public static String getDefaultEndpoint(String provider) {
    switch (provider.toLowerCase()) {
      case PROVIDER_OPENAI:
        return DEFAULT_OPENAI_ENDPOINT;
      case PROVIDER_ANTHROPIC:
        return DEFAULT_ANTHROPIC_ENDPOINT;
      default:
        throw new IllegalArgumentException("Unsupported provider: " + provider);
    }
  }
}
