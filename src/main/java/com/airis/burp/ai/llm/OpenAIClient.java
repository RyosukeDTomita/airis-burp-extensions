package com.airis.burp.ai.llm;

import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpRequestResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

/** OpenAI Client to send requests to the OpenAI API */
public class OpenAIClient implements LLMClient {
  private static final String DEFAULT_MODEL = "gpt-4o-mini";
  private static final int DEFAULT_TIMEOUT = 30000;
  private static final String SYSTEM_PROMPT =
      "You are an expert security analyst specializing in web application security."
          + "Following the user's prompt, analyze the provided HTTP request and response.\n";
  private int timeout = DEFAULT_TIMEOUT;

  // Track active connections for cleanup during extension unload
  private static final Set<HttpURLConnection> activeConnections =
      Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

  /**
   * analyze the given HTTP request and response using the OpenAI API
   *
   * @param request
   * @param userPrompt
   * @return
   */
  public String analyze(
      ConfigModel config, HttpRequestResponse requestAndResponse, String userPrompt) {

    if (!config.isValid()) {
      return "[ERROR] Configuration is incomplete. Please configure API settings.";
    }

    String response;
    if (requestAndResponse == null) {
      return "[ERROR] requestAndResponse is null";
    } else if (userPrompt == null || userPrompt.trim().isEmpty()) {
      return "[ERROR] userPrompt is null or empty";
    }

    try {
      String jsonRequest = formatRequest(requestAndResponse, userPrompt);
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
   * @param HttpRequestResponse
   * @param userPrompt
   * @return
   */
  private String formatRequest(HttpRequestResponse request, String userPrompt) {
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
   * Send HTTP request to OpenAI API and get the result as a string
   *
   * @param jsonRequest
   * @return
   */
  private String sendHttpRequest(ConfigModel config, String jsonRequest) {
    HttpURLConnection connection = null;
    try {
      URL url = new URL(config.getEndpoint());
      connection = (HttpURLConnection) url.openConnection();

      // Track this connection for cleanup during unload
      activeConnections.add(connection);

      // Set request method and headers
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Authorization", "Bearer " + config.getApiKey());
      connection.setDoOutput(true);
      connection.setConnectTimeout(timeout);
      connection.setReadTimeout(timeout);

      // Send request
      try (OutputStream os = connection.getOutputStream()) {
        byte[] input = jsonRequest.getBytes("utf-8");
        os.write(input, 0, input.length);
      }

      // Check response code
      int responseCode = connection.getResponseCode();
      StringBuilder response = new StringBuilder();

      // Read response (success or error)
      BufferedReader br = null;
      try {
        if (responseCode >= 200 && responseCode < 300) {
          // Success response
          br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
        } else {
          // Error response
          br = new BufferedReader(new InputStreamReader(connection.getErrorStream(), "utf-8"));
        }

        String responseLine;
        while ((responseLine = br.readLine()) != null) {
          response.append(responseLine);
        }
      } finally {
        if (br != null) {
          br.close();
        }
      }

      // If error response, throw with detailed error
      if (responseCode >= 400) {
        String errorMsg = "HTTP " + responseCode + " Error: " + response.toString();
        throw new RuntimeException(errorMsg);
      }

      return response.toString();

    } catch (Exception e) {
      throw new RuntimeException("Failed to make HTTP request: " + e.getMessage(), e);
    } finally {
      // Remove from active connections and disconnect
      if (connection != null) {
        activeConnections.remove(connection);
        connection.disconnect();
      }
    }
  }

  /**
   * TODO
   *
   * @param request
   * @return
   */
  private String formatHttpData(HttpRequestResponse request) {
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

  /**
   * Close all active HTTP connections. Called during extension unload to ensure proper resource
   * cleanup.
   */
  public static void closeAllConnections() {
    synchronized (activeConnections) {
      for (HttpURLConnection connection : activeConnections) {
        try {
          connection.disconnect();
        } catch (Exception e) {
          // Ignore errors during cleanup
        }
      }
      activeConnections.clear();
    }
  }
}
