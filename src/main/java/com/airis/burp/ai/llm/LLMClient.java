package com.airis.burp.ai.llm;

import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;

/** Interface for LLM client implementations. */
public interface LLMClient {
  /**
   * Analyze an HTTP request/response pair using the AI model.
   *
   * @param request The HTTP request/response data
   * @param userPrompt The user prompt for analysis
   * @return Analysis response from the AI model
   */
  String analyze(ConfigModel configModel, HttpHistoryItem requestResponse);
}
