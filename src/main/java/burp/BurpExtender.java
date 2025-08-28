package burp;

import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.ui.ConfigurationTab;
import com.airis.burp.ai.ui.RepeaterContextMenuFactory;

/**
 * Main entry point for the Burp Suite AI Extension.
 * This class implements IBurpExtender to integrate with Burp Suite.
 * 
 * Note: Must be in package "burp" and named "BurpExtender" for Burp Suite to recognize it.
 */
public class BurpExtender implements IBurpExtender {
    
    private static final String EXTENSION_NAME = "airis";
    
    private IBurpExtenderCallbacks callbacks;
    private ConfigManager configManager;
    private AnalysisEngine analysisEngine;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        try {
            // Set extension name
            callbacks.setExtensionName(EXTENSION_NAME);
            
            // Initialize components
            initializeComponents();
            
            // Add configuration tab
            ConfigurationTab configTab = new ConfigurationTab(configManager, analysisEngine);
            callbacks.addSuiteTab(configTab);
            
            // Register context menu factory for Repeater integration
            RepeaterContextMenuFactory menuFactory = new RepeaterContextMenuFactory(callbacks, analysisEngine);
            callbacks.registerContextMenuFactory(menuFactory);
            
            // Print startup message
            callbacks.printOutput("airis extension loaded successfully");
            callbacks.printOutput("Version: 1.0.0");
            callbacks.printOutput("Configure your LLM settings in the airis tab");
            
        } catch (Exception e) {
            callbacks.printError("Failed to load airis extension: " + e.getMessage());
            e.printStackTrace(callbacks.getStderr());
        }
    }
    
    private void initializeComponents() {
        // Initialize configuration manager
        this.configManager = new ConfigManager();
        
        // Initialize analysis engine
        this.analysisEngine = new AnalysisEngine(configManager);
        
        callbacks.printOutput("Core components initialized successfully");
    }
    
    public ConfigManager getConfigManager() {
        return configManager;
    }
    
    public AnalysisEngine getAnalysisEngine() {
        return analysisEngine;
    }
}