package com.airis.burp.ai;

import com.airis.burp.ai.config.ConfigManager;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

/**
 * Main entry point for the Burp Suite AI Extension using old Extender API.
 * This class implements IBurpExtender for backward compatibility.
 * For new Montoya API support, use MontoyaExtension instead.
 * 
 * @deprecated Use MontoyaExtension for new implementations
 */
@Deprecated
public class BurpExtender implements IBurpExtender {
    private static final String EXTENSION_NAME = "airis";
    
    private ConfigManager configManager;
    private IBurpExtenderCallbacks callbacks;

    /**
     * Called by Burp Suite when the extension is loaded.
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME);

        // Initialize components
        initializeComponents();
        
        // Print startup message
        callbacks.printOutput(EXTENSION_NAME + " extension loaded successfully (using legacy API)");
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

}