package com.airis.burp.ai.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.AnthropicClient;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;
import java.util.concurrent.ExecutorService;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** chose LLM provider and start analysis. */
public class AnalysisEngine {
  private final Supplier<ConfigModel> configModelSupplier;
  private final Logging logging;
  private final MontoyaApi montoyaApi;
  private final ExecutorService executorService;

  public AnalysisEngine(
      Supplier<ConfigModel> configModelSupplier, Logging logging, MontoyaApi montoyaApi, ExecutorService executorService) {
    this.configModelSupplier = configModelSupplier;
    this.logging = logging;
    this.montoyaApi = montoyaApi;
    this.executorService = executorService;
  }

  /**
   * Internal method for AI analysis. Use analyzeAsync() for public API.
   * Package-private for testing purposes.
   *
   * @param request The HTTP request to analyze
   * @param response The HTTP response to analyze (nullable)
   * @return Analysis result or error message
   */
  String analyze(String request, String response) {
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
   * Analyze request/response asynchronously
   *
   * @param request The HTTP request to analyze
   * @param response The HTTP response to analyze (nullable)
   * @param callback Callback to handle the result
   */
  public void analyzeAsync(String request, String response, Consumer<String> callback) {
    executorService.submit(() -> {
      try {
        String result = analyze(request, response);
        javax.swing.SwingUtilities.invokeLater(() -> callback.accept(result));
      } catch (Exception e) {
        logging.logToError("Async analysis failed: " + e.getMessage());
        javax.swing.SwingUtilities.invokeLater(() -> callback.accept("Analysis failed: " + e.getMessage()));
      }
    });
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
