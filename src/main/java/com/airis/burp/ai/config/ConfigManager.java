package com.airis.burp.ai.config;

/**
 * Manager for configuration operations including loading, saving, and validation.
 */
public class ConfigManager {
    private static final String DEFAULT_CONFIG_PATH = "burp_ai_config.json";
    private static final String DEFAULT_SYSTEM_PROMPT = 
        "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, " +
        "potential issues, and provide recommendations. Focus on common web application security issues like " +
        "injection attacks, authentication bypasses, authorization issues, and data exposure.";
    
    private final String configPath;
    private final SecureStorage secureStorage;

    public ConfigManager() {
        this(DEFAULT_CONFIG_PATH);
    }

    public ConfigManager(String configPath) {
        this.configPath = configPath;
        this.secureStorage = new SecureStorage();
    }

    public ConfigModel loadConfig() {
        ConfigModel config = secureStorage.load(configPath);
        
        // Set default system prompt if empty
        if (config.getSystemPrompt().isEmpty()) {
            config.setSystemPrompt(DEFAULT_SYSTEM_PROMPT);
        }
        
        return config;
    }

    public void saveConfig(ConfigModel config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        secureStorage.save(config, configPath);
    }

    public String encryptApiKey(String apiKey) {
        if (apiKey == null) {
            return "";
        }
        return secureStorage.encrypt(apiKey);
    }

    public String decryptApiKey(String encryptedApiKey) {
        if (encryptedApiKey == null || encryptedApiKey.isEmpty()) {
            return "";
        }
        return secureStorage.decrypt(encryptedApiKey);
    }

    public boolean validateConfig(ConfigModel config) {
        if (config == null) {
            return false;
        }
        
        // Check if configuration is complete
        if (!config.isComplete()) {
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

    public String getDefaultSystemPrompt() {
        return DEFAULT_SYSTEM_PROMPT;
    }

    public ConfigModel createDefaultConfig() {
        ConfigModel config = new ConfigModel();
        config.setSystemPrompt(DEFAULT_SYSTEM_PROMPT);
        return config;
    }
}