package com.airis.burp.ai.config;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration model for AI Extension settings. Contains provider, endpoint, API key, and user
 * prompt information.
 */
public class ConfigModel {
  private static final List<String> VALID_PROVIDERS =
      Arrays.asList("openai", "anthropic", "gemini");

  // Default endpoints for different providers
  public static final String DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions";
  public static final String DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages";
  public static final String DEFAULT_GEMINI_ENDPOINT =
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent";

  public static final String DEFAULT_USER_PROMPT =
      "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, "
          + "potential issues, and provide recommendations. Focus on common web application security issues like "
          + "injection attacks, authentication bypasses, authorization issues, and data exposure.";

  private String provider = "openai"; // OpenAI or Anthropic or Gemini
  private String endpoint = DEFAULT_OPENAI_ENDPOINT;
  private String apiKey = ""; // Plain text API key (stored in memory only)
  private String userPrompt = "";

  public ConfigModel() {
    setProvider("openai");
    setEndpoint(DEFAULT_OPENAI_ENDPOINT);
    setApiKey("");
    setUserPrompt(DEFAULT_USER_PROMPT);
  }

  /**
   * @param userPrompt Custom user prompt for analysis The other parameters(provider, endpoint,
   *     apiKey) vary depending on the user, so they are set to default values.
   */
  public ConfigModel(String userPrompt) {
    setProvider("openai");
    setEndpoint(DEFAULT_OPENAI_ENDPOINT);
    setApiKey("");
    setUserPrompt(userPrompt);
  }

  public String getProvider() {
    return provider;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public String getApiKey() {
    return apiKey;
  }

  public String getUserPrompt() {
    return userPrompt;
  }

  public void setProvider(String provider) {
    this.provider = provider;
    // Update endpoint when provider changes
    if ("openai".equals(provider)) {
      this.endpoint = DEFAULT_OPENAI_ENDPOINT;
    } else if ("anthropic".equals(provider)) {
      this.endpoint = DEFAULT_ANTHROPIC_ENDPOINT;
    } else if ("gemini".equals(provider)) {
      this.endpoint = DEFAULT_GEMINI_ENDPOINT;
    }
  }

  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint;
  }

  public void setApiKey(String apiKey) {
    this.apiKey = apiKey;
  }

  public void setUserPrompt(String userPrompt) {
    this.userPrompt = userPrompt;
  }

  public boolean isValid() {
    // null and empty checks
    if (provider == null || provider.isEmpty()) {
      return false;
    }
    if (endpoint == null || endpoint.isEmpty()) {
      return false;
    }
    if (apiKey == null || apiKey.isEmpty()) {
      return false;
    }
    if (userPrompt == null || userPrompt.isEmpty()) {
      return false;
    }
    return true;
  }
}
