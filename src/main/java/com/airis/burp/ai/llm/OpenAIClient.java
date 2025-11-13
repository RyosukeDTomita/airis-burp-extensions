package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;

/** OpenAI Client to send requests to the OpenAI API */
public class OpenAIClient extends AbstractLLMClient {
  private static final String DEFAULT_MODEL = "gpt-4o-mini";

  /**
   * Constructor
   *
   * @param montoyaApi Burp's Montoya API instance
   */
  public OpenAIClient(MontoyaApi montoyaApi) {
    super(montoyaApi);
  }

  @Override
  protected String formatRequestBody(
      ConfigModel configModel, HttpHistoryItem requestAndResponse, String userPrompt) {

    StringBuilder json = new StringBuilder();
    json.append("{\n");
    json.append("  \"model\": \"").append(DEFAULT_MODEL).append("\",\n");
    json.append("  \"messages\": [\n");

    // System prompt - defines AI's role
    json.append("    {\n");
    json.append("      \"role\": \"system\",\n");
    json.append("      \"content\": \"").append(escapeJson(DEFAULT_SYSTEM_PROMPT)).append("\"\n");
    json.append("    },\n");

    // User message with custom prompt + HTTP data
    json.append("    {\n");
    json.append("      \"role\": \"user\",\n");
    StringBuilder userContent = new StringBuilder();
    userContent.append(userPrompt).append("\\n\\n");
    userContent.append(formatHttpData(requestAndResponse));
    json.append("      \"content\": \"").append(escapeJson(userContent.toString())).append("\"\n");

    json.append("    }\n");
    json.append("  ],\n");
    json.append("  \"max_tokens\": 1000,\n");
    json.append("  \"temperature\": 0.3\n");
    json.append("}");
    
    String jsonString = json.toString();
    montoyaApi.logging().logToOutput("[DEBUG] JSON length: " + jsonString.length() + " bytes");
    montoyaApi.logging().logToOutput("[DEBUG] JSON is valid: " + jsonString.endsWith("}"));
    montoyaApi.logging().logToOutput("Request JSON: " + jsonString);
    return jsonString;
  }

  @Override
  protected String parseResponseBody(String jsonResponse) {
    // montoyaApi.logging().logToOutput("Response JSON: " + jsonResponse);
    try {
      // Look for content field in choices array
      String searchKey = "\"content\":";
      int startIndex = jsonResponse.indexOf(searchKey);
      if (startIndex == -1) {
        return "No content found in response";
      }

      // Skip to the start of the value
      startIndex += searchKey.length();

      // Skip whitespace and opening quote
      while (startIndex < jsonResponse.length()
          && (jsonResponse.charAt(startIndex) == ' '
              || jsonResponse.charAt(startIndex) == '\t'
              || jsonResponse.charAt(startIndex) == '\n')) {
        startIndex++;
      }

      if (startIndex >= jsonResponse.length() || jsonResponse.charAt(startIndex) != '"') {
        return "Invalid JSON format";
      }
      startIndex++; // Skip opening quote

      // Find the end of the string value
      StringBuilder content = new StringBuilder();
      boolean escaped = false;

      for (int i = startIndex; i < jsonResponse.length(); i++) {
        char c = jsonResponse.charAt(i);

        if (escaped) {
          if (c == 'n') content.append('\n');
          else if (c == 't') content.append('\t');
          else if (c == 'r') content.append('\r');
          else if (c == '\\') content.append('\\');
          else if (c == '"') content.append('"');
          else content.append(c);
          escaped = false;
        } else if (c == '\\') {
          escaped = true;
        } else if (c == '"') {
          // End of string
          break;
        } else {
          content.append(c);
        }
      }

      String result = content.toString();
      return result.isEmpty() ? "Empty response from AI" : result;

    } catch (Exception e) {
      return "Error parsing response: " + e.getMessage();
    }
  }
}
