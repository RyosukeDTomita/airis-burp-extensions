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

  /** Default constructor */
  public ConfigModel() {
    setProvider("openai");
    setEndpoint("");
    setApiKey("");
    setUserPrompt(DEFAULT_USER_PROMPT);
  }

  /**
   * Copy constructor to create a snapshot of the configuration Used to ensure thread safety during
   * analysis
   *
   * @param other The ConfigModel to copy from
   */
  public ConfigModel(ConfigModel other) {
    if (other != null) {
      this.provider = other.provider;
      this.endpoint = other.endpoint;
      this.apiKey = other.apiKey;
      this.userPrompt = other.userPrompt;
    }
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

  /**
   * Returns a string representation of the ConfigModel with masked API key
   *
   * @return String representation of ConfigModel
   */
  @Override
  public String toString() {
    String FORMAT = "ConfigModel(provider=%s, endpoint=%s, apiKey=%s, userPrompt=%s)";
    return String.format(FORMAT, provider, endpoint, maskApiKey(apiKey), userPrompt);
  }

  /**
   * Masks the API key by showing only the last 4 characters
   *
   * @param key API key to mask
   * @return masked API key
   */
  private String maskApiKey(String key) {
    if (key == null || key.isEmpty()) {
      return "***";
    }
    if (key.length() <= 4) {
      return "***" + key;
    }
    return "***" + key.substring(key.length() - 4);
  }

  /**
   * Checks equality based on all configuration fields
   *
   * @param obj The object to compare with
   * @return true if all fields are equal
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }

    ConfigModel other = (ConfigModel) obj;

    // Compare provider
    if (provider == null) {
      if (other.provider != null) {
        return false;
      }
    } else if (!provider.equals(other.provider)) {
      return false;
    }

    // Compare endpoint
    if (endpoint == null) {
      if (other.endpoint != null) {
        return false;
      }
    } else if (!endpoint.equals(other.endpoint)) {
      return false;
    }

    // Compare apiKey
    if (apiKey == null) {
      if (other.apiKey != null) {
        return false;
      }
    } else if (!apiKey.equals(other.apiKey)) {
      return false;
    }

    // Compare userPrompt
    if (userPrompt == null) {
      if (other.userPrompt != null) {
        return false;
      }
    } else if (!userPrompt.equals(other.userPrompt)) {
      return false;
    }

    return true;
  }

  /**
   * Generates hash code based on all configuration fields
   *
   * @return hash code
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((provider == null) ? 0 : provider.hashCode());
    result = prime * result + ((endpoint == null) ? 0 : endpoint.hashCode());
    result = prime * result + ((apiKey == null) ? 0 : apiKey.hashCode());
    result = prime * result + ((userPrompt == null) ? 0 : userPrompt.hashCode());
    return result;
  }
}
