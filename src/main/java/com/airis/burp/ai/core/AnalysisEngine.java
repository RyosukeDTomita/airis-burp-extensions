package com.airis.burp.ai.core;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;

public class AnalysisEngine {
  private final ConfigModel configModel;
  private final Logging logging;
  private final RequestProcessor requestProcessor;
  private volatile boolean isAnalyzing = false;

  public AnalysisEngine(
      RequestProcessor requestProcessor, ConfigModel configModel, Logging logging) {
    this.configModel = configModel;
    this.logging = logging;
    this.requestProcessor = requestProcessor;
  }

  /**
   * Main method to initiate AI analysis of HTTP request/response
   *
   * @param request The HTTP request to analyze
   * @param response The HTTP response to analyze (nullable)
   * @return Analysis result or error message
   */
  public String analyzeRequest(String request, String response) {
    if (isAnalyzing) {
      return "Analysis already in progress. Please wait...";
    }

    try {
      isAnalyzing = true;
      logging.logToOutput("Starting AI analysis...");

      // Validate configuration
      if (!configModel.isValid()) {
        return "Configuration is incomplete. Please configure API settings.";
      }

      // Create LLM client based on provider
      LLMClient llmClient = createLLMClient(configModel.getProvider());
      if (llmClient == null) {
        return "Unsupported AI provider: " + configModel.getProvider();
      }

      // Setup client
      llmClient.setEndpoint(configModel.getEndpoint());
      llmClient.setApiKey(configModel.getApiKey());

      // Create analysis target using RequestProcessor
      AnalysisTarget target = requestProcessor.createAnalysisRequest(request, response);

      // Execute analysis
      AnalysisResult result = llmClient.analyze(target, configModel.getUserPrompt());
      logging.logToOutput("Analysis completed successfully");

      return result != null ? result.getAnalysis() : "No analysis result";

    } catch (Exception e) {
      logging.logToError("Analysis failed: " + e.getMessage());
      return "Analysis failed: " + e.getMessage();
    } finally {
      isAnalyzing = false;
    }
  }

  /**
   * Build the complete prompt for AI analysis
   *
   * @param request HTTP request content
   * @param response HTTP response content (nullable)
   * @return Complete prompt string
   */
  private String buildAnalysisPrompt(String request, String response) {
    StringBuilder promptBuilder = new StringBuilder();

    // Add user-defined prompt
    String userPrompt = configModel.getUserPrompt();
    if (userPrompt != null && !userPrompt.isEmpty()) {
      promptBuilder.append(userPrompt).append("\n\n");
    }

    // Add request
    promptBuilder.append("=== HTTP Request ===\n");
    promptBuilder.append(request).append("\n\n");

    // Add response if available
    if (response != null && !response.isEmpty()) {
      promptBuilder.append("=== HTTP Response ===\n");
      promptBuilder.append(response).append("\n");
    }

    return promptBuilder.toString();
  }

  /**
   * Create appropriate LLM client based on provider
   *
   * @param provider The AI provider name
   * @return LLM client instance or null if unsupported
   */
  private LLMClient createLLMClient(String provider) {
    if (provider == null) {
      return null;
    }

    switch (provider.toLowerCase()) {
      case "openai":
        return new OpenAIClient();
      case "anthropic":
        // TODO: Implement AnthropicClient
        logging.logToError("Anthropic client not yet implemented");
        return null;
      case "gemini":
        // TODO: Implement GeminiClient
        logging.logToError("Gemini client not yet implemented");
        return null;
      default:
        logging.logToError("Unknown AI provider: " + provider);
        return null;
    }
  }

  /**
   * Check if analysis is currently in progress
   *
   * @return true if analyzing, false otherwise
   */
  public boolean isAnalyzing() {
    return isAnalyzing;
  }

  public ConfigModel getConfigModel() {
    return configModel;
  }

  public Logging getLogging() {
    return logging;
  }

  public RequestProcessor getRequestProcessor() {
    return requestProcessor;
  }
}
