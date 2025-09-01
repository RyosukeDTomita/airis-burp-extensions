package com.airis.burp.ai.core;

import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;

/**
 * Core analysis engine that orchestrates request processing and AI analysis.
 */
public class AnalysisEngine {
    private final ConfigManager configManager;
    private LLMClient llmClient;
    private RequestProcessor requestProcessor;

    public AnalysisEngine(RequestProcessor requestProcessor, ConfigManager configManager) {
        this.configManager = configManager;
        this.requestProcessor = requestProcessor;
        initializeLLMClient();
    }

    private void initializeLLMClient() {
        // For now, default to OpenAI client
        // In the future, this could be factory-based depending on provider
        this.llmClient = new OpenAIClient();
        
        try {
            ConfigModel config = configManager.loadConfig();
            if (config != null && !config.getApiKey().isEmpty()) {
                llmClient.setEndpoint(config.getEndpoint());
                String apiKey = configManager.retrieveApiKey(config.getApiKey());
                llmClient.setApiKey(apiKey);
            }
        } catch (Exception e) {
            // Failed to load config, continue with default empty client
        }
    }

    public AnalysisResponse analyzeRequest(AnalysisRequest request) {
        AnalysisResponse response = new AnalysisResponse();
        
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
                    if (config.getSystemPrompt() == null || config.getSystemPrompt().isEmpty()) {
                        errorMsg.append("System prompt is not set. ");
                    }
                }
                
                errorMsg.append("Please check your settings in the AI Security Analyzer tab.");
                response.setAnalysis(errorMsg.toString());
                response.setResponseTime(0);
                return response;
            }

            // Sanitize sensitive data
            AnalysisRequest sanitizedRequest = sanitizeRequest(request);
            
            // Ensure LLM client has the latest configuration
            if (llmClient != null) {
                llmClient.setEndpoint(config.getEndpoint());
                String decryptedApiKey = configManager.decryptApiKey(config.getApiKey());
                llmClient.setApiKey(decryptedApiKey);
            }
            
            // Perform AI analysis
            response = llmClient.analyze(sanitizedRequest, config.getSystemPrompt());
            
        } catch (Exception e) {
            // Return error response with detailed error message
            response.setAnalysis("Error during AI analysis: " + e.getMessage());
            response.setResponseTime(0);
        }
        
        return response;
    }

    public AnalysisResponse analyzeHttpTraffic(String httpRequest, String httpResponse) {
        AnalysisRequest analysisRequest = requestProcessor.createAnalysisRequest(httpRequest, httpResponse);
        return analyzeRequest(analysisRequest);
    }

    /**
     * Convenience method for analyzing request and response data.
     * This is an alias for analyzeHttpTraffic for better API clarity.
     */
    public String analyzeRequestResponse(String httpRequest, String httpResponse) {
        AnalysisResponse response = analyzeHttpTraffic(httpRequest, httpResponse);
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

    private AnalysisRequest sanitizeRequest(AnalysisRequest request) {
        if (request == null) {
            return new AnalysisRequest();
        }

        AnalysisRequest sanitized = new AnalysisRequest();
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