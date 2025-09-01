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
    private ConfigModel currentConfig;

    // TODO: コンストラクタ1つにまとめられそう。
    public ConfigManager() {
        this(DEFAULT_CONFIG_PATH);
    }

    public ConfigManager(String configPath) {
        this.configPath = configPath;
    }

    public ConfigModel loadConfig() {
        // Return current in-memory config if exists
        if (currentConfig != null) {
            return currentConfig;
        }
        
        // Otherwise create default config
        currentConfig = createDefaultConfig();
        return currentConfig;
    }

    public void saveConfig(ConfigModel config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        // Store encrypted API key
        if (config.getApiKey() != null && !config.getApiKey().isEmpty()) {
            String encryptedKey = encryptApiKey(config.getApiKey());
            config.setApiKey(encryptedKey);
        }
        // Save to in-memory storage
        this.currentConfig = config;
    }

    public String encryptApiKey(String apiKey) {
        if (apiKey == null) {
            return "";
        }
        // TODO: Implement API key encryption logic without SecureStorage
        return apiKey;
    }

    public String decryptApiKey(String encryptedApiKey) {
        if (encryptedApiKey == null || encryptedApiKey.isEmpty()) {
            return "";
        }
        // TODO: Implement API key decryption logic without SecureStorage
        return encryptedApiKey;
    }

    /**
     * Store the API key securely (currently just encrypts it).
     * @param apiKey The API key to store
     * @return The encrypted API key
     */
    public String storeApiKey(String apiKey) {
        return encryptApiKey(apiKey);
    }

    /**
     * Retrieve the API key (currently just decrypts it).
     * @param encryptedKey The encrypted API key to retrieve
     * @return The decrypted API key
     */
    public String retrieveApiKey(String encryptedKey) {
        return decryptApiKey(encryptedKey);
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
        if (config.getSystemPrompt() == null || config.getSystemPrompt().isEmpty()) {
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