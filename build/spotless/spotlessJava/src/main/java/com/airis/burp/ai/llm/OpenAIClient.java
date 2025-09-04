package com.airis.burp.ai.llm;

import com.airis.burp.ai.core.AnalysisResult;
import com.airis.burp.ai.core.AnalysisTarget;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

/** OpenAI API client implementation. */
public class OpenAIClient implements LLMClient {
  private static final String DEFAULT_MODEL = "gpt-4o-mini";
  private static final int DEFAULT_TIMEOUT = 30000;
  private String endpoint = "";
  private String apiKey = "";
  private int timeout = DEFAULT_TIMEOUT;

  public AnalysisResult analyze(AnalysisTarget request, String userPrompt) {
    AnalysisResult response = new AnalysisResult();
    if (request == null || userPrompt == null || userPrompt.trim().isEmpty()) {
      response.setAnalysis("");
      response.setResponseTime(0);
      return response;
    }

    long startTime = System.currentTimeMillis();
    try {
      String jsonRequest = formatRequest(request, userPrompt);
      String jsonResponse = makeHttpRequest(jsonRequest);
      response = parseResponse(jsonResponse);
    } catch (Exception e) {
      response.setAnalysis("API request failed: " + e.getMessage());
      // TODO
    }
    long endTime = System.currentTimeMillis();
    response.setResponseTime(endTime - startTime);
    return response;
  }

  public String formatRequest(AnalysisTarget request, String userPrompt) {
    StringBuilder json = new StringBuilder();
    json.append("{\n");
    json.append("  \"model\": \"").append(DEFAULT_MODEL).append("\",\n");
    json.append("  \"messages\": [\n");
    json.append("    {\n");
    json.append("      \"role\": \"system\",\n");
    json.append("      \"content\": \"").append(escapeJson(userPrompt)).append("\"\n");
    json.append("    },\n");
    json.append("    {\n");
    json.append("      \"role\": \"user\",\n");
    json.append("      \"content\": \"").append(escapeJson(formatHttpData(request))).append("\"\n");
    json.append("    }\n");
    json.append("  ],\n");
    json.append("  \"max_tokens\": 1000,\n");
    json.append("  \"temperature\": 0.3\n");
    json.append("}");

    return json.toString();
  }

  public AnalysisResult parseResponse(String jsonResponse) {
    AnalysisResult response = new AnalysisResult();

    try {
      // Simple JSON parsing for the response
      String content = extractContent(jsonResponse);
      response.setAnalysis(content);
    } catch (Exception e) {
      response.setAnalysis("");
    }

    return response;
  }

  protected String makeHttpRequest(String jsonRequest) {
    if (endpoint.isEmpty() || apiKey.isEmpty()) {
      throw new RuntimeException("Endpoint or API key not configured");
    }

    try {
      URL url = new URL(endpoint);
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();

      // Set request method and headers
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Authorization", "Bearer " + apiKey);
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
    }
  }

  private String formatHttpData(AnalysisTarget request) {
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

  // LLMClient interface methods
  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint != null ? endpoint : "";
  }

  public String getEndpoint() {
    return endpoint;
  }

  public void setApiKey(String apiKey) {
    this.apiKey = apiKey != null ? apiKey : "";
  }

  public String getApiKey() {
    return apiKey;
  }

  public void setTimeout(int timeoutMs) {
    this.timeout = timeoutMs;
  }

  public int getTimeout() {
    return timeout;
  }
}
