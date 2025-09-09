package com.airis.burp.ai.config;

/**
 * DTO for AI Extension settings. Contains provider, endpoint, API key, and user prompt information.
 */
public class ConfigModel {

  public static final String DEFAULT_USER_PROMPT =
      "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, "
          + "potential issues, and provide recommendations. Focus on common web application security issues like "
          + "injection attacks, authentication bypasses, authorization issues, and data exposure.";

  private String provider = "openai"; // OpenAI or Anthropic or Gemini
  private String endpoint = ""; // API endpoint URL
  private String apiKey = ""; // Plain text API key (stored in memory only)
  private String userPrompt = "";

  /** Default constructor initializing with default values */
  public ConfigModel() {
    setProvider("openai");
    setEndpoint("");
    setApiKey("");
    setUserPrompt(DEFAULT_USER_PROMPT);
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

  /**
   * Validate the configuration
   *
   * @return boolean
   */
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
