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
            logging.logToOutput("Initializing components...");
            
            // Initialize ConfigManager first
            this.configManager = new ConfigManager();
            logging.logToOutput("ConfigManager initialized");
            
            // Initialize LLMClient
            this.llmClient = new OpenAIClient();
            logging.logToOutput("LLMClient initialized");
            
            // Initialize RequestProcessor with LLMClient
            this.requestProcessor = new RequestProcessor(llmClient);
            logging.logToOutput("RequestProcessor initialized");
            
            // Initialize AnalysisEngine with RequestProcessor and ConfigManager
            this.analysisEngine = new AnalysisEngine(requestProcessor, configManager);
            logging.logToOutput("AnalysisEngine initialized");
            
            // Verify all components are initialized
            if (configManager == null || llmClient == null || 
                requestProcessor == null || analysisEngine == null) {
                throw new IllegalStateException("One or more components failed to initialize");
            }
            
            logging.logToOutput("All components initialized successfully");
        } catch (Exception e) {
            logging.logToError("Failed to initialize components: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Extension initialization failed", e);
        }
    }
    /**
     * Registers the UI components for the extension.
     */
    private void registerUIComponents() {
        try {
            // Verify required components are initialized
            if (analysisEngine == null) {
                logging.logToError("Cannot register UI components: AnalysisEngine is null");
                throw new IllegalStateException("AnalysisEngine must be initialized before registering UI components");
            }
            
            if (configManager == null) {
                logging.logToError("Cannot register UI components: ConfigManager is null");
                throw new IllegalStateException("ConfigManager must be initialized before registering UI components");
            }
            
            // Register configuration tab
            ConfigurationTab configTab = new ConfigurationTab(configManager, logging);
            api.userInterface().registerSuiteTab(EXTENSION_NAME + " Config", configTab.getComponent());
            logging.logToOutput("Configuration tab registered");

            // Register context menu
            AIAnalysisMenuProvider contextMenuProvider = new AIAnalysisMenuProvider(
                analysisEngine,
                configManager,
                api
            );
            api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
            logging.logToOutput("Context menu provider registered");

            logging.logToOutput("UI components registered successfully");
        } catch (Exception e) {
            logging.logToError("Failed to register UI components: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("UI registration failed", e);
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