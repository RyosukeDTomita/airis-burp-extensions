package com.airis.burp.ai.llm;

import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;

/** Interface for LLM client implementations. */
public interface LLMClient {
  /**
   * Analyze an HTTP request/response pair using the AI model with default prompt.
   *
   * @param configModel Configuration model containing API settings
   * @param requestResponse The HTTP request/response data
   * @return Analysis response from the AI model
   */
  String analyze(ConfigModel configModel, HttpHistoryItem requestResponse);

  /**
   * Analyze an HTTP request/response pair using the AI model with custom prompt.
   *
   * @param configModel Configuration model containing API settings
   * @param requestResponse The HTTP request/response data
   * @param customPrompt Custom user prompt for analysis
   * @return Analysis response from the AI model
   */
  String analyze(ConfigModel configModel, HttpHistoryItem requestResponse, String customPrompt);
}
