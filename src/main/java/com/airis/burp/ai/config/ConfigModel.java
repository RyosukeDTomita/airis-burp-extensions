package com.airis.burp.ai.config;

import com.airis.burp.ai.llm.LLMProviderRegistry;
import java.util.Objects;

/** DTO for AI Extension settings. Contains provider, endpoint, and API key information. */
public final class ConfigModel {

  private final String provider;
  private final String endpoint;
  private final String model;
  private final String apiKey;

  // Lazy initialized hash code for performance optimization.
  // Initialized to 0 by default when the instance is created.
  private int hashCode;

  /** Do not use default constructor */
  public ConfigModel() {
    throw new UnsupportedOperationException("Default constructor is not supported.");
  }

  /**
   * Fully parameterized constructor accepting API key as a character array.
   *
   * @param provider The LLM provider (e.g., "openai").
   * @param endpoint The API endpoint URL.
   * @param apiKey The API key
   */
  public ConfigModel(
      final String provider, final String endpoint, final String model, final String apiKey) {
    if (!isValidProvider(provider)) {
      throw new IllegalArgumentException("Invalid provider specified.");
    }
    if (!isValidEndpoint(endpoint)) {
      throw new IllegalArgumentException("Endpoint must be a valid HTTPS URL.");
    }
    if (model == null || model.trim().isEmpty()) {
      throw new IllegalArgumentException("Model cannot be null or empty.");
    }
    if (apiKey == null || apiKey.trim().isEmpty()) {
      throw new IllegalArgumentException("API key cannot be null or empty.");
    }

    this.provider = provider;
    this.endpoint = endpoint;
    this.model = model;
    this.apiKey = apiKey;
  }

  public String getProvider() {
    return provider;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public String getModel() {
    return model;
  }

  public String getApiKey() {
    return apiKey;
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

    // Note: java.net.URI doesn't provide validation-only methods, so we use try-catch
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
   * Returns a string representation of the ConfigModel with masked API key The string consists of
   * all fields except the API key, which is masked for security. Format is
   * "ConfigModel(provider=%s, endpoint=%s, apiKey=%s)", where provider is openai or anthoropic,
   * endpoint is LLM API endpoint URL, apiKey is masked API key.
   *
   * @return String representation of ConfigModel
   */
  @Override
  public String toString() {
    String FORMAT = "ConfigModel(provider=%s, endpoint=%s, model=%s, apiKey=%s)";
    return String.format(FORMAT, provider, endpoint, model, maskApiKey());
  }

  /**
   * Masks the API key by showing only the last 4 characters
   *
   * @param key API key to mask
   * @return masked API key
   */
  private String maskApiKey() {
    if (this.apiKey.length() <= 4) {
      return "***";
    }
    String tail = this.apiKey.substring(this.apiKey.length() - 4);
    return "***" + tail;
  }

  /**
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

    if (!Objects.equals(model, other.model)) {
      return false;
    }

    if (!Objects.equals(apiKey, other.apiKey)) {
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
    result = prime * result + ((model == null) ? 0 : model.hashCode());
    result = prime * result + ((apiKey == null) ? 0 : apiKey.hashCode());
    hashCode = result;
    return result;
  }
}
