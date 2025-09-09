package com.airis.burp.ai.core;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;

/** TODO: あとでかく */
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
   * Entry point of AI analysis
   *
   * @param request The HTTP request to analyze
   * @param response The HTTP response to analyze (nullable)
   * @return Analysis result or error message
   */
  public String analyzeRequest(String request, String response) {
    // Prevent concurrent analysis
    if (isAnalyzing) {
      return "Analysis already in progress. Please wait...";
    }

    try {
      isAnalyzing = true;
      logging.logToOutput("Starting AI analysis...");

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

      // Execute analysis
      AnalysisTarget requestResponse = requestProcessor.createAnalysisRequest(request, response);
      AnalysisResult result = llmClient.analyze(requestResponse, configModel.getUserPrompt());
      logging.logToOutput("Analysis completed successfully");
      if (result == null) {
        return "No analysis result returned from LLM client.";
      } else {
        return result.getAnalysis();
      }

    } catch (Exception e) {
      logging.logToError("Analysis failed: " + e.getMessage());
      return "Analysis failed: " + e.getMessage();
    } finally {
      this.isAnalyzing = false; // Reset analyzing flag
    }
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
   * Get LLM analysis is already running
   *
   * @return true if analyzing, false otherwise
   */
  public boolean isAnalyzing() {
    return isAnalyzing;
  }

  // TODO: テスト用
  public ConfigModel getConfigModel() {
    return configModel;
  }

  // TODO: テスト用
  public Logging getLogging() {
    return logging;
  }

  // TODO: テスト用
  public RequestProcessor getRequestProcessor() {
    return requestProcessor;
  }
}
