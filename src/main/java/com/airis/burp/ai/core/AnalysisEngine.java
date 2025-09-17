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
  private volatile boolean isAnalyzing = false;

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

      // Create a snapshot of the configuration to ensure thread safety
      ConfigModel configSnapshot = new ConfigModel(configModel);

      // Create LLM client based on provider
      LLMClient llmClient = createLLMClient(configSnapshot.getProvider());
      if (llmClient == null) {
        return "Unsupported AI provider: " + configSnapshot.getProvider();
      }

      // Execute analysis using the configuration snapshot
      HttpHistoryItem requestResponse = HttpHistoryItem.fromHttpRequestResponse(request, response);
      String result = llmClient.analyze(configSnapshot, requestResponse);
      logging.logToOutput("Analysis completed successfully");
      if (result == null) {
        return "No analysis result returned from LLM client.";
      } else {
        return result;
      }

    } catch (Exception e) {
      logging.logToError("Analysis failed: " + e.getMessage());
      return "Analysis failed: " + e.getMessage();
    } finally {
      this.isAnalyzing = false; // Reset analyzing flag
    }
  }

  /**
   * Factory method to create appropriate LLM client based on provider
   *
   * @param provider
   * @return
   */
  private LLMClient createLLMClient(String provider) {
    if (provider == null || provider.isEmpty()) {
      logging.logToError("Provider is not configured");
      return null;
    }

    switch (provider) {
      case "openai":
        return new OpenAIClient(montoyaApi);
      case "anthropic":
        // TODO: Implement Anthropic client with MontoyaApi
        logging.logToError("Anthropic provider is not yet implemented");
        return new AnthropicClient(montoyaApi);
      default:
        logging.logToError("Unknown provider: " + provider);
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
}
