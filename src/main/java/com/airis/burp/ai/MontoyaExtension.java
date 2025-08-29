package com.airis.burp.ai;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.extension.Extension;
import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.ui.ConfigurationTab;
import com.airis.burp.ai.ui.RepeaterContextMenuFactory;
import com.airis.burp.ai.core.RequestProcessor;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;

/**
 * Main entry point for the Burp Suite AI Extension using Montoya API.
 * This class implements BurpExtension to integrate with Burp Suite.
 */
public class MontoyaExtension implements BurpExtension {
    private static final String EXTENSION_NAME = "airis";
    
    private MontoyaApi api;
    private ConfigManager configManager;
    private LLMClient llmClient;
    private RequestProcessor requestProcessor;
    private AnalysisEngine analysisEngine;
    private Logging logging;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        
        // Set extension name
        api.extension().setName(EXTENSION_NAME);
        
        // Initialize components
        initializeComponents();
        
        // Register UI components
        registerUIComponents();
        
        // Print startup message
        logging.logToOutput(EXTENSION_NAME + " extension loaded successfully using Montoya API");
    }
    
    private void initializeComponents() {
        try {
            // Initialize configuration manager
            this.configManager = new ConfigManager();
            
            // Initialize LLM client
            this.llmClient = new OpenAIClient();
            
            // Initialize request processor
            this.requestProcessor = new RequestProcessor(llmClient);
            
            // Initialize analysis engine
            this.analysisEngine = new AnalysisEngine(requestProcessor, configManager);
            
            logging.logToOutput("All components initialized successfully");
        } catch (Exception e) {
            logging.logToError("Failed to initialize components: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void registerUIComponents() {
        try {
            // Register configuration tab
            ConfigurationTab configTab = new ConfigurationTab(configManager, logging);
            api.userInterface().registerSuiteTab(EXTENSION_NAME + " Config", configTab.getComponent());
            
            // Register context menu
            RepeaterContextMenuFactory contextMenuFactory = new RepeaterContextMenuFactory(
                analysisEngine, 
                configManager, 
                api
            );
            api.userInterface().registerContextMenuItemsProvider(contextMenuFactory);
            
            logging.logToOutput("UI components registered successfully");
        } catch (Exception e) {
            logging.logToError("Failed to register UI components: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public ConfigManager getConfigManager() {
        return configManager;
    }
    
    public String getExtensionName() {
        return EXTENSION_NAME;
    }
    
    public MontoyaApi getApi() {
        return api;
    }
}