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
   * Performs AI analysis on HTTP request/response with custom prompt.
   * Public for use by UI components.
   *
   * @param request The HTTP request to analyze (required)
   * @param response The HTTP response to analyze (nullable) TODO: Optionalに書き換える?
   * @param customPrompt Custom user prompt (required)
   * @return Analysis result or error message
   */
  public String analyze(String request, String response, String customPrompt) {
    logging.logToOutput("Starting AI analysis...");
    if (customPrompt == null || customPrompt.trim().isEmpty()) {
      logging.logToOutput("No custom prompt provided, using default prompt.");
      return "Error: Custom prompt is empty.";
    }

    // create llm client based on provider
    ConfigModel configModel = configModelSupplier.get();
    LLMClient llmClient;
    try {
      llmClient = createLLMClient(configModel.getProvider());
    } catch (IllegalArgumentException e) {
      logging.logToError("Analysis failed: " + e.getMessage());
      throw new RuntimeException("Unsupported AI provider: " + e.getMessage(), e);
    }
    // Execute analysis using the configuration snapshot
    HttpHistoryItem httpHistoryItem = HttpHistoryItem.fromHttpRequestResponse(request, response);
    String result;
    result = llmClient.analyze(configModel, httpHistoryItem, customPrompt);
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
