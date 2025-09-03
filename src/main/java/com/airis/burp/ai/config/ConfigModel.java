package com.airis.burp.ai.config;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration model for AI Extension settings.
 * Contains provider, endpoint, API key, and user prompt information.
 */
public class ConfigModel {
    private static final List<String> VALID_PROVIDERS = Arrays.asList("openai", "anthropic");

    private String provider = ""; // OpenAI or Anthropic or Gemini
    private String endpoint = "";
    private String apiKey = "";  // Plain text API key (stored in memory only)
    private String userPrompt = "";

    // Getters
    public String getProvider() {
        return provider;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getApiKey() {
        return apiKey;
    }

    // Deprecated - kept for backward compatibility
    @Deprecated
    public String getEncryptedApiKey() {
        return apiKey;
    }

    public String getUserPrompt() {
        return userPrompt;
    }

    // Setters with null safety
    public void setProvider(String provider) {
        this.provider = provider != null ? provider : "";
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint != null ? endpoint : "";
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey != null ? apiKey : "";
    }

    // Deprecated - kept for backward compatibility
    @Deprecated
    public void setEncryptedApiKey(String apiKey) {
        this.apiKey = apiKey != null ? apiKey : "";
    }

    public void setUserPrompt(String userPrompt) {
        this.userPrompt = userPrompt != null ? userPrompt : "";
    }

    // Validation methods
    public boolean isValidProvider(String provider) {
        return provider != null && VALID_PROVIDERS.contains(provider.toLowerCase());
    }

    public boolean isValidEndpoint(String endpoint) {
        if (endpoint == null || endpoint.trim().isEmpty()) {
            return false;
        }
        return endpoint.startsWith("https://");
    }

    /**
     * Checks if all required configuration fields are filled.
     * @return true if all fields are non-empty, false otherwise
     */
    public boolean isComplete() {
        return !provider.isEmpty() && 
               !endpoint.isEmpty() && 
               !apiKey.isEmpty() && 
               !userPrompt.isEmpty();
    }
}