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

  private String provider = ""; // OpenAI or Anthropic or Gemini
  private String endpoint = "";
  private String apiKey = ""; // Plain text API key (stored in memory only)
  private String userPrompt = "";

  /**
   * @param userPrompt Custom user prompt for analysis The other parameters(provider, endpoint,
   *     apiKey) vary depending on the user, so they are set to empty strings by default.
   */
  public ConfigModel(String userPrompt) {
    setProvider("");
    setEndpoint("");
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
}
