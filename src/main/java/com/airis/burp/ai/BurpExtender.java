package com.airis.burp.ai;

import com.airis.burp.ai.config.ConfigManager;

/**
 * Main entry point for the Burp Suite AI Extension.
 * This class implements IBurpExtender to integrate with Burp Suite.
 */
public class BurpExtender {
    private static final String EXTENSION_NAME = "airis";
    
    private ConfigManager configManager;
    private Object callbacks; // Using Object to avoid Burp API dependency for testing

    /**
     * Called by Burp Suite when the extension is loaded.
     */
    public void registerExtenderCallbacks(Object callbacks) {
        this.callbacks = callbacks;
        
        // Set extension name
        try {
            // Use reflection to call setExtensionName method
            callbacks.getClass().getMethod("setExtensionName", String.class)
                    .invoke(callbacks, EXTENSION_NAME);
        } catch (Exception e) {
            // Handle reflection errors gracefully
            System.err.println("Failed to set extension name: " + e.getMessage());
        }

        // Initialize components
        initializeComponents();
        
        // Print startup message
        printOutput("airis extension loaded successfully");
    }

    private void initializeComponents() {
        // Initialize configuration manager
        this.configManager = new ConfigManager();
        
        // TODO: Initialize other components
        // - UI components (ConfigurationTab, AnalysisDialog)
        // - LLM clients
        // - Request processor
        // - Analysis engine
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public String getExtensionName() {
        return EXTENSION_NAME;
    }

    private void printOutput(String message) {
        try {
            if (callbacks != null) {
                callbacks.getClass().getMethod("printOutput", String.class)
                        .invoke(callbacks, message);
            }
        } catch (Exception e) {
            // Fallback to console if Burp callbacks are not available
            System.out.println(message);
        }
    }

    private void printError(String message) {
        try {
            if (callbacks != null) {
                callbacks.getClass().getMethod("printError", String.class)
                        .invoke(callbacks, message);
            }
        } catch (Exception e) {
            // Fallback to console if Burp callbacks are not available
            System.err.println(message);
        }
    }
}