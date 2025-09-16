package com.airis.burp.ai.llm;

/** Registry for available LLM providers. Manages supported providers and their clients. */
public class LLMProviderRegistry {

  /** Enum for supported LLM providers */
  public enum Provider {
    OPENAI,
    ANTHROPIC,
    GEMINI
  }

  // Provider types (for backward compatibility)
  public static final String PROVIDER_OPENAI = "openai";
  public static final String PROVIDER_ANTHROPIC = "anthropic";
  public static final String PROVIDER_GEMINI = "gemini";

  // Default endpoints for different providers
  public static final String DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";
  public static final String DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages";
  public static final String DEFAULT_GEMINI_ENDPOINT =
      "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent";

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
      case PROVIDER_GEMINI:
        return Provider.GEMINI;
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
      case PROVIDER_GEMINI:
        return DEFAULT_GEMINI_ENDPOINT;
      default:
        throw new IllegalArgumentException("Unsupported provider: " + provider);
    }
  }
}
