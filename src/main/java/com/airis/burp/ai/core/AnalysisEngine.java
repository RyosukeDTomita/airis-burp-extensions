package com.airis.burp.ai.core;

import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;
import burp.api.montoya.logging.Logging;

/**
 * Core analysis engine that orchestrates request processing and AI analysis.
 */
public class AnalysisEngine {
    private final ConfigManager configManager;
    private final Logging logging;
    private LLMClient llmClient;
    private RequestProcessor requestProcessor;

    public AnalysisEngine(RequestProcessor requestProcessor, ConfigManager configManager, Logging logging) {
        this.configManager = configManager;
        this.logging = logging;
        this.requestProcessor = requestProcessor;
        initializeLLMClient();
    }

    /**
     * 
     */
    private void initializeLLMClient() {
        this.llmClient = new OpenAIClient();
        try {
            ConfigModel config = configManager.loadConfig();
            if (config == null) {
                // Log warning but don't throw exception
                logging.logToOutput("Warning: ConfigModel is null, using default configuration");
                return;
            }
            if (config.getApiKey().isEmpty()) {
                // Log warning but don't throw exception
                logging.logToOutput("Warning: API key is not set in configuration. Please configure API key in the extension settings.");
                return;
            }
            llmClient.setEndpoint(config.getEndpoint());
            llmClient.setApiKey(config.getApiKey());
            logging.logToOutput("LLM client initialized successfully");
        } catch (Exception e) {
            // Log error but don't throw exception
            logging.logToError("Warning: Failed to initialize LLM client: " + e.getMessage());
        }
    }

    public AnalysisResult analyzeRequest(AnalysisTarget request) {
        AnalysisResult response = new AnalysisResult();
        
        if (request == null) {
            response.setAnalysis("");
            response.setResponseTime(0);
            return response;
        }

        try {
            ConfigModel config = configManager.loadConfig();
            
            // Validate configuration with detailed error messages
            if (!configManager.validateConfig(config)) {
                StringBuilder errorMsg = new StringBuilder("Configuration validation failed. ");
                
                if (config == null) {
                    errorMsg.append("Configuration is not initialized.");
                } else {
                    if (config.getProvider() == null || config.getProvider().isEmpty()) {
                        errorMsg.append("Provider is not set. ");
                    }
                    if (config.getEndpoint() == null || config.getEndpoint().isEmpty()) {
                        errorMsg.append("API endpoint is not set. ");
                    }
                    if (config.getApiKey() == null || config.getApiKey().isEmpty()) {
                        errorMsg.append("API key is not set. ");
                    }
                    if (config.getUserPrompt() == null || config.getUserPrompt().isEmpty()) {
                        errorMsg.append("User prompt is not set. ");
                    }
                }
                
                errorMsg.append("Please check your settings in the AI Security Analyzer tab.");
                response.setAnalysis(errorMsg.toString());
                response.setResponseTime(0);
                return response;
            }

            // Sanitize sensitive data
            AnalysisTarget sanitizedRequest = sanitizeRequest(request);
            
            // Ensure LLM client has the latest configuration
            if (llmClient != null) {
                llmClient.setEndpoint(config.getEndpoint());
                llmClient.setApiKey(config.getApiKey());
            }
            
            // Perform AI analysis
            response = llmClient.analyze(sanitizedRequest, config.getUserPrompt());
            
        } catch (Exception e) {
            // Return error response with detailed error message
            response.setAnalysis("Error during AI analysis: " + e.getMessage());
            response.setResponseTime(0);
        }
        
        return response;
    }

    public AnalysisResult analyzeHttpTraffic(String httpRequest, String httpResponse) {
        AnalysisTarget analysisRequest = requestProcessor.createAnalysisRequest(httpRequest, httpResponse);
        return analyzeRequest(analysisRequest);
    }

    /**
     * Convenience method for analyzing request and response data.
     * This is an alias for analyzeHttpTraffic for better API clarity.
     */
    public String analyzeRequestResponse(String httpRequest, String httpResponse) {
        AnalysisResult response = analyzeHttpTraffic(httpRequest, httpResponse);
        return response.getAnalysis();
    }

    public void setConfiguration(ConfigModel config) {
        if (config != null) {
            configManager.saveConfig(config);
            initializeLLMClient(); // Reinitialize with new config
        }
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public void setLLMClient(LLMClient llmClient) {
        this.llmClient = llmClient;
    }

    private AnalysisTarget sanitizeRequest(AnalysisTarget request) {
        if (request == null) {
            return new AnalysisTarget();
        }

        AnalysisTarget sanitized = new AnalysisTarget();
        sanitized.setMethod(request.getMethod());
        sanitized.setUrl(request.getUrl());
        sanitized.setHeaders(request.getHeaders());
        sanitized.setStatusCode(request.getStatusCode());
        
        // Sanitize body and response body
        sanitized.setBody(requestProcessor.sanitizeData(request.getBody()));
        sanitized.setResponseBody(requestProcessor.sanitizeData(request.getResponseBody()));
        
        return sanitized;
    }
}