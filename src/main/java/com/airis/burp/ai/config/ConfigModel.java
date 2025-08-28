package com.airis.burp.ai.config;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration model for AI Extension settings.
 * Contains provider, endpoint, API key, and system prompt information.
 */
public class ConfigModel {
    private static final List<String> VALID_PROVIDERS = Arrays.asList("openai", "anthropic");
    
    private String provider = "";
    private String endpoint = "";
    private String encryptedApiKey = "";
    private String systemPrompt = "";

    // Getters
    public String getProvider() {
        return provider;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getEncryptedApiKey() {
        return encryptedApiKey;
    }

    public String getSystemPrompt() {
        return systemPrompt;
    }

    // Setters with null safety
    public void setProvider(String provider) {
        this.provider = provider != null ? provider : "";
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint != null ? endpoint : "";
    }

    public void setEncryptedApiKey(String encryptedApiKey) {
        this.encryptedApiKey = encryptedApiKey != null ? encryptedApiKey : "";
    }

    public void setSystemPrompt(String systemPrompt) {
        this.systemPrompt = systemPrompt != null ? systemPrompt : "";
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
               !encryptedApiKey.isEmpty() && 
               !systemPrompt.isEmpty();
    }
}