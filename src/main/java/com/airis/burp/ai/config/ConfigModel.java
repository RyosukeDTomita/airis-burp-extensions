package com.airis.burp.ai.config;

import com.airis.burp.ai.llm.LLMProviderRegistry;

/**
 * DTO for AI Extension settings. Contains provider, endpoint, API key, and user prompt information.
 */
public final class ConfigModel {

  public static final String DEFAULT_USER_PROMPT =
      "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, "
          + "potential issues, and provide recommendations. Focus on common web application security issues like "
          + "injection attacks, authentication bypasses, authorization issues, and data exposure.";

  private final String provider;
  private final String endpoint;
  private final String apiKey;
  private final String userPrompt;

  // Lazy initialized hash code for performance optimization.
  // Initialized to 0 by default when the instance is created.
  private int hashCode;

  /** Do not use default constructor */
  public ConfigModel() {
    throw new UnsupportedOperationException("Default constructor is not supported.");
  }

  /**
   * Fully parameterized constructor for creating an immutable ConfigModel.
   *
   * @param provider The LLM provider (e.g., "openai").
   * @param endpoint The API endpoint URL.
   * @param apiKey The API key.
   * @param userPrompt The user-defined prompt.
   * @throws IllegalArgumentException if any parameter is invalid.
   */
  public ConfigModel(
      final String provider, final String endpoint, final String apiKey, final String userPrompt) {
    if (!isValidProvider(provider)) {
      throw new IllegalArgumentException("Invalid provider specified.");
    }
    if (!isValidEndpoint(endpoint)) {
      throw new IllegalArgumentException("Endpoint must be a valid HTTPS URL.");
    }
    if (apiKey == null || apiKey.trim().isEmpty()) {
      throw new IllegalArgumentException("API key cannot be null or empty.");
    }
    if (userPrompt == null || userPrompt.trim().isEmpty()) {
      throw new IllegalArgumentException("User prompt cannot be null or empty.");
    }

    this.provider = provider;
    this.endpoint = endpoint;
    this.apiKey = apiKey;
    this.userPrompt = userPrompt;
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

  /**
   * Checks if the provider string is a valid LLM provider. NOTE: This method call when constructing
   * the object, so it needs to get `provider` from argument.
   *
   * @param providerString The provider string to check.
   * @return true if valid, false otherwise.
   */
  private static boolean isValidProvider(final String provider) {
    if (provider == null || provider.trim().isEmpty()) {
      return false;
    }
    try {
      // TODO: 専用のメソッドを作って例外を挙げない
      LLMProviderRegistry.Provider.valueOf(provider.toUpperCase());
      return true;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Validates if the endpoint URL is properly formatted and uses an acceptable protocol. NOTE: This
   * method call when constructing the object, so it needs to get `endpoint` from argument.
   *
   * @param endpoint The endpoint URL to validate.
   * @return true if the endpoint is valid, false otherwise.
   */
  private static boolean isValidEndpoint(final String endpoint) {
    if (endpoint == null || endpoint.trim().isEmpty()) {
      return false;
    }

    // TODO: 例外をあげずに検証できる方法がないか?
    try {
      java.net.URI uri = new java.net.URI(endpoint.trim());
      String scheme = uri.getScheme();

      if (scheme == null || !scheme.equalsIgnoreCase("https")) {
        return false;
      }

      String host = uri.getHost();
      if (host == null || host.trim().isEmpty()) {
        return false;
      }

      int port = uri.getPort();
      if (port != -1 && (port < 1 || port > 65535)) {
        return false;
      }

      return true;
    } catch (java.net.URISyntaxException e) {
      return false;
    }
  }

  /**
   * Returns a string representation of the ConfigModel with masked API key
   *
   * @return String representation of ConfigModel
   */
  @Override
  public String toString() {
    String FORMAT = "ConfigModel(provider=%s, endpoint=%s, apiKey=%s, userPrompt=%s)";
    return String.format(FORMAT, provider, endpoint, maskApiKey(), userPrompt);
  }

  /**
   * Masks the API key by showing only the last 4 characters
   *
   * @param key API key to mask
   * @return masked API key
   */
  private String maskApiKey() {
    if (this.apiKey == null || this.apiKey.isEmpty()) {
      return "***";
    }
    if (this.apiKey.length() <= 4) {
      return "***" + this.apiKey;
    }
    return "***" + this.apiKey.substring(this.apiKey.length() - 4);
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
   * Generates hash code based on all configuration fields using lazy initialization.
   *
   * @return hash code
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = hashCode;

    // Return cached
    if (hashCode != 0) {
      return result;
    }
    result = prime * result + ((provider == null) ? 0 : provider.hashCode());
    result = prime * result + ((endpoint == null) ? 0 : endpoint.hashCode());
    result = prime * result + ((apiKey == null) ? 0 : apiKey.hashCode());
    result = prime * result + ((userPrompt == null) ? 0 : userPrompt.hashCode());
    hashCode = result;
    return result;
  }
}
