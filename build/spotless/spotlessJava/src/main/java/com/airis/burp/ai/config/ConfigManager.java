package com.airis.burp.ai.config;

/** Manager for configuration operations including loading, saving, and validation. */
public class ConfigManager {
  private static final String DEFAULT_USER_PROMPT =
      "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, "
          + "potential issues, and provide recommendations. Focus on common web application security issues like "
          + "injection attacks, authentication bypasses, authorization issues, and data exposure.";
  private ConfigModel currentConfig;

  public ConfigModel loadConfig() {
    // Return current in-memory config if exists
    if (currentConfig != null) {
      return currentConfig;
    }

    currentConfig = new ConfigModel(DEFAULT_USER_PROMPT);
    return currentConfig;
  }

  public void saveConfig(ConfigModel config) {
    if (config == null) {
      throw new IllegalArgumentException("Configuration cannot be null");
    }
    this.currentConfig = config;
  }

  public boolean validateConfig(ConfigModel config) {
    if (config == null) {
      return false;
    }

    // Check basic fields
    if (config.getProvider() == null || config.getProvider().isEmpty()) {
      return false;
    }
    if (config.getEndpoint() == null || config.getEndpoint().isEmpty()) {
      return false;
    }
    if (config.getApiKey() == null || config.getApiKey().isEmpty()) {
      return false;
    }
    if (config.getUserPrompt() == null || config.getUserPrompt().isEmpty()) {
      return false;
    }

    // Validate provider
    if (!config.isValidProvider(config.getProvider())) {
      return false;
    }

    // Validate endpoint
    if (!config.isValidEndpoint(config.getEndpoint())) {
      return false;
    }

    return true;
  }

  public String getDefaultUserPrompt() {
    return DEFAULT_USER_PROMPT;
  }
}
