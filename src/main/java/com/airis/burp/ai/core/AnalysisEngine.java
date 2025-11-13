package com.airis.burp.ai.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.AnthropicClient;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;
import java.util.function.Supplier;

/** chose LLM provider and start analysis. */
public class AnalysisEngine {
  private final Supplier<ConfigModel> configModelSupplier;
  private final Logging logging;
  private final MontoyaApi montoyaApi;

  public AnalysisEngine(
      Supplier<ConfigModel> configModelSupplier, Logging logging, MontoyaApi montoyaApi) {
    this.configModelSupplier = configModelSupplier;
    this.logging = logging;
    this.montoyaApi = montoyaApi;
  }

  /**
   * Performs AI analysis on HTTP request/response.
   * Public for use by UI components.
   *
   * @param request The HTTP request to analyze
   * @param response The HTTP response to analyze (nullable)
   * @return Analysis result or error message
   */
  public String analyze(String request, String response) {
    logging.logToOutput("Starting AI analysis...");
    ConfigModel configModel = configModelSupplier.get();

    // Create LLM client based on provider
    LLMClient llmClient;
    try {
      llmClient = createLLMClient(configModel.getProvider());
    } catch (IllegalArgumentException e) {
      logging.logToError("Analysis failed: " + e.getMessage());
      throw new RuntimeException("Unsupported AI provider: " + e.getMessage(), e);
    }
    // Execute analysis using the configuration snapshot
    HttpHistoryItem httpHistoryItem = HttpHistoryItem.fromHttpRequestResponse(request, response);
    String result = llmClient.analyze(configModel, httpHistoryItem);
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
