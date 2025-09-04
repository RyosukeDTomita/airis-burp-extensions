package com.airis.burp.ai.llm;

import com.airis.burp.ai.core.AnalysisResult;
import com.airis.burp.ai.core.AnalysisTarget;

/** Interface for LLM client implementations. */
public interface LLMClient {
  /**
   * Analyze an HTTP request/response pair using the AI model.
   *
   * @param request The HTTP request/response data
   * @param userPrompt The user prompt for analysis
   * @return Analysis response from the AI model
   */
  AnalysisResult analyze(AnalysisTarget request, String userPrompt);

  /**
   * Set the API endpoint URL.
   *
   * @param endpoint The endpoint URL
   */
  void setEndpoint(String endpoint);

  /**
   * Get the API endpoint URL.
   *
   * @return The endpoint URL
   */
  String getEndpoint();

  /**
   * Set the API key for authentication.
   *
   * @param apiKey The API key
   */
  void setApiKey(String apiKey);

  /**
   * Get the API key for authentication.
   *
   * @return The API key
   */
  String getApiKey();

  /**
   * Set the request timeout in milliseconds.
   *
   * @param timeoutMs Timeout in milliseconds
   */
  void setTimeout(int timeoutMs);

  /**
   * Get the request timeout in milliseconds.
   *
   * @return Timeout in milliseconds
   */
  int getTimeout();
}
