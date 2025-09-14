package com.airis.burp.ai.llm;

import java.util.*;

/** Registry for available LLM providers. Manages supported providers and their clients. */
public class LLMProviderRegistry {

  // Provider types
  public static final String PROVIDER_OPENAI = "openai";
  public static final String PROVIDER_ANTHROPIC = "anthropic";
  public static final String PROVIDER_GEMINI = "gemini";

  // Default endpoints for different providers
  public static final String DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";
  public static final String DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages";
  public static final String DEFAULT_GEMINI_ENDPOINT =
      "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent";

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
