package com.airis.burp.ai;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.ui.ConfigurationTab;
import com.airis.burp.ai.ui.AIAnalysisMenuProvider;
import com.airis.burp.ai.core.RequestProcessor;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;

/**
 * Main entry point for the Burp Suite AI Extension using Montoya API.
 * This class implements BurpExtension to integrate with Burp Suite.
 */
public class Extension implements BurpExtension {
    private static final String EXTENSION_NAME = "airis";
    
    private MontoyaApi api;
    private ConfigManager configManager;
    private LLMClient llmClient;
    private RequestProcessor requestProcessor;
    private AnalysisEngine analysisEngine;
    private Logging logging;
    
    /**
     * `initialize()` runs when Burp loads your extension.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        api.extension().setName(EXTENSION_NAME);
        initializeComponents();
        registerUIComponents();
        logging.logToOutput(EXTENSION_NAME + " extension loaded successfully using Montoya API");
    }
    
    /**
     * Initializes the core components of the extension.
     */
    private void initializeComponents() {
        try {
            this.configManager = new ConfigManager();
            this.llmClient = new OpenAIClient();
            this.requestProcessor = new RequestProcessor(llmClient);
            this.analysisEngine = new AnalysisEngine(requestProcessor, configManager, logging);
            logging.logToOutput("All components initialized successfully");
        } catch (Exception e) {
            logging.logToError("Failed to initialize components: " + e.getMessage());
            e.printStackTrace();
        }
    }
    /**
     * Registers the UI components for the extension.
     */
    private void registerUIComponents() {
        try {
            // Register configuration tab
            ConfigurationTab configTab = new ConfigurationTab(configManager, logging);
            api.userInterface().registerSuiteTab(EXTENSION_NAME + " Config", configTab.getComponent());
            
            // Register context menu
            AIAnalysisMenuProvider contextMenuProvider = new AIAnalysisMenuProvider(
                analysisEngine, 
                configManager, 
                api
            );
            api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
            
            logging.logToOutput("UI components registered successfully");
        } catch (Exception e) {
            logging.logToError("Failed to register UI components: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // TODO: テストのためだけのpublicなので消す
    public ConfigManager getConfigManager() {
        return configManager;
    }
    
    // TODO: テストのためだけのpublicなので消す
    public String getExtensionName() {
        return EXTENSION_NAME;
    }
    
    // TODO: テストのためだけのpublicなので消す
    public MontoyaApi getApi() {
        return api;
    }
}