package com.airis.burp.ai.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.AnthropicClient;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;

/** chose LLM provider and start analysis. */
public class AnalysisEngine {
  private final ConfigModel configModel;
  private final Logging logging;
  private final MontoyaApi montoyaApi;

  public AnalysisEngine(ConfigModel configModel, Logging logging, MontoyaApi montoyaApi) {
    this.configModel = configModel;
    this.logging = logging;
    this.montoyaApi = montoyaApi;
  }

  /**
   * Entry point of AI analysis
   *
   * @param request The HTTP request to analyze
   * @param response The HTTP response to analyze (nullable)
   * @return Analysis result or error message
   */
  public String analyze(String request, String response) {
    logging.logToOutput("Starting AI analysis...");
    if (!configModel.isValid()) {
      return "Configuration is incomplete. Please configure API settings.";
    }
    // Create a snapshot of the configuration to ensure thread safety
    ConfigModel configSnapshot = new ConfigModel(configModel);

    // Create LLM client based on provider
    LLMClient llmClient;
    try {
      llmClient = createLLMClient(configSnapshot.getProvider());
    } catch (IllegalArgumentException e) {
      logging.logToError("Analysis failed: " + e.getMessage());
      throw new RuntimeException("Unsupported AI provider: " + e.getMessage(), e);
    }
    // Execute analysis using the configuration snapshot
    HttpHistoryItem httpHistoryItem = HttpHistoryItem.fromHttpRequestResponse(request, response);
    String result = llmClient.analyze(configSnapshot, httpHistoryItem);
    if (result == null) {
      return "No analysis result returned from LLM client.";
    } else {
      return result;
    }
  }

  /**
   * Factory method to create appropriate LLM client based on provider
   *
   * @param provider
   * @return
   */
  private LLMClient createLLMClient(String provider) {
    switch (provider) {
      case "openai":
        return new OpenAIClient(montoyaApi);
      case "anthropic":
        return new AnthropicClient(montoyaApi);
      default:
        throw new IllegalArgumentException("Unsupported provider: " + provider);
    }
  }
}
