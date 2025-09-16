package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;
import java.util.Map;

/** OpenAI Client to send requests to the OpenAI API */
public class OpenAIClient implements LLMClient {
  private static final String DEFAULT_MODEL = "gpt-4o-mini"; // TODO
  private static final String SYSTEM_PROMPT =
      "You are an expert security analyst specializing in web application security."
          + "Following the user's prompt, analyze the provided HTTP request and response.\n";
  private final MontoyaApi montoyaApi;

  /**
   * Constructor
   *
   * @param montoyaApi Burp's Montoya API instance
   */
  public OpenAIClient(MontoyaApi montoyaApi) {
    this.montoyaApi = montoyaApi;
  }

  /**
   * analyze the given HTTP request and response using the OpenAI API
   *
   * @param config Configuration model containing API settings and user prompt
   * @param requestAndResponse HTTP request and response data
   * @return
   */
  public String analyze(ConfigModel config, HttpHistoryItem requestAndResponse) {

    if (!config.isValid()) {
      return "[ERROR] Configuration is incomplete. Please configure API settings.";
    }

    String response;
    if (requestAndResponse == null) {
      return "[ERROR] requestAndResponse is null";
    }

    String userPrompt = config.getUserPrompt();
    if (userPrompt == null || userPrompt.trim().isEmpty()) {
      return "[ERROR] userPrompt is null or empty";
    }

    try {
      String jsonRequest = formatRequest(requestAndResponse, config.getUserPrompt());
      String jsonResponse = sendHttpRequest(config, jsonRequest);
      response = parseResponse(jsonResponse);
    } catch (Exception e) {
      response = "[ERROR] API request failed: " + e.getMessage();
      // TODO: Implement error handling
    }
    return response;
  }

  /**
   * Create JSON request body for OpenAI API
   *
   * @param HttpHistoryItem
   * @param userPrompt
   * @return
   */
  private String formatRequest(HttpHistoryItem request, String userPrompt) {
    StringBuilder json = new StringBuilder();
    json.append("{\n");
    json.append("  \"model\": \"").append(DEFAULT_MODEL).append("\",\n");
    json.append("  \"messages\": [\n");

    // System prompt - セキュリティ分析の基本指示
    json.append("    {\n");
    json.append("      \"role\": \"system\",\n");
    json.append("      \"content\": \"").append(escapeJson(SYSTEM_PROMPT)).append("\"\n");
    json.append("    },\n");

    // User prompt - ユーザーからの追加指示とHTTPデータを含む
    json.append("    {\n");
    json.append("      \"role\": \"user\",\n");

    // ユーザープロンプトとHTTPデータを結合
    StringBuilder userContent = new StringBuilder();
    if (userPrompt != null && !userPrompt.isEmpty()) {
      userContent.append(userPrompt).append("\n\n");
    }
    userContent.append(formatHttpData(request));

    json.append("      \"content\": \"").append(escapeJson(userContent.toString())).append("\"\n");
    json.append("    }\n");

    json.append("  ],\n");
    json.append("  \"max_tokens\": 1000,\n");
    json.append("  \"temperature\": 0.3\n");
    json.append("}");

    return json.toString();
  }

  /**
   * parse the JSON response from OpenAI API.
   *
   * @param jsonResponse
   * @return
   */
  private String parseResponse(String jsonResponse) {
    String response;
    try {
      // Simple JSON parsing for the response
      response = extractContent(jsonResponse);
    } catch (Exception e) {
      response = "";
      // TODO: Implement error handling
    }
    return response;
  }

  /**
   * Send HTTP request to OpenAI API using Montoya API
   *
   * @param config Configuration containing endpoint and API key
   * @param jsonRequest JSON request body
   * @return JSON response string
   */
  private String sendHttpRequest(ConfigModel config, String jsonRequest) {
    try {
      // Build HTTP request using Montoya API
      HttpRequest httpRequest =
          HttpRequest.httpRequestFromUrl(config.getEndpoint())
              .withMethod("POST")
              .withHeader("Content-Type", "application/json")
              .withHeader("Authorization", "Bearer " + config.getApiKey())
              .withBody(jsonRequest);

      // Send request through Burp's HTTP client
      HttpRequestResponse requestResponse = montoyaApi.http().sendRequest(httpRequest);

      // Get response
      HttpResponse httpResponse = requestResponse.response();

      if (httpResponse == null) {
        throw new RuntimeException("No response received from API");
      }

      // Check response status
      int statusCode = httpResponse.statusCode();
      String responseBody = httpResponse.bodyToString();

      // If error response, throw with detailed error
      if (statusCode >= 400) {
        String errorMsg = "HTTP " + statusCode + " Error: " + responseBody;
        throw new RuntimeException(errorMsg);
      }

      return responseBody;

    } catch (Exception e) {
      throw new RuntimeException("Failed to make HTTP request: " + e.getMessage(), e);
    }
  }

  /**
   * TODO
   *
   * @param request
   * @return
   */
  private String formatHttpData(HttpHistoryItem request) {
    StringBuilder data = new StringBuilder();

    data.append(
        "Please analyze this HTTP request and response for security vulnerabilities and potential issues:\\n\\n");

    data.append("=== HTTP REQUEST ===\\n");
    data.append(request.getMethod()).append(" ").append(request.getUrl()).append("\\n");

    // Add headers
    if (!request.getHeaders().isEmpty()) {
      data.append("\\nHeaders:\\n");
      for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
        data.append(header.getKey()).append(": ").append(header.getValue()).append("\\n");
      }
    }

    // Add request body if present
    if (!request.getBody().isEmpty()) {
      data.append("\\nRequest Body:\\n");
      data.append(request.getBody()).append("\\n");
    }

    data.append("\\n=== HTTP RESPONSE ===\\n");
    data.append("Status Code: ").append(request.getStatusCode()).append("\\n");

    // Add response body if present
    if (!request.getResponseBody().isEmpty()) {
      data.append("\\nResponse Body:\\n");
      data.append(request.getResponseBody()).append("\\n");
    }

    data.append("\\n=== ANALYSIS REQUEST ===\\n");
    data.append("Please provide a detailed security analysis covering:\\n");
    data.append("1. Potential vulnerabilities (SQL injection, XSS, etc.)\\n");
    data.append("2. Authentication and authorization issues\\n");
    data.append("3. Input validation problems\\n");
    data.append("4. Information disclosure risks\\n");
    data.append("5. Any other security concerns\\n");

    return data.toString();
  }

  /**
   * Parse json response from OpenAI
   *
   * @param jsonResponse
   * @return
   */
  private String extractContent(String jsonResponse) {
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

  private String escapeJson(String text) {
    if (text == null) return "";
    return text.replace("\\", "\\\\") // Must be first
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\b", "\\b")
        .replace("\f", "\\f");
  }
}
