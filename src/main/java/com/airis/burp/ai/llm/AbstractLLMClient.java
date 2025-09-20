package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;
import java.util.Map;

/** Abstract base class for LLM client implementations. */
public abstract class AbstractLLMClient implements LLMClient {
  protected final MontoyaApi montoyaApi;

  /**
   * Constructor
   *
   * @param montoyaApi Burp's Montoya API instance
   */
  protected AbstractLLMClient(MontoyaApi montoyaApi) {
    this.montoyaApi = montoyaApi;
  }

  /**
   * Analyze an HTTP request/response pair using the AI model.
   *
   * @param configModel Configuration model containing API settings
   * @param requestAndResponse HTTP request and response data
   * @return Analysis response from the AI model
   */
  @Override
  public String analyze(ConfigModel configModel, HttpHistoryItem requestAndResponse) {
    if (!configModel.isValid()) {
      return "[ERROR] Configuration is incomplete. Please configure API settings.";
    }

    if (requestAndResponse == null) {
      return "[ERROR] requestAndResponse is null";
    }

    // TODO: そのうち、UserPromptはConfigModelから切り離して、リクエストごとに指定できるようにする
    String userPrompt = configModel.getUserPrompt();
    if (userPrompt == null || userPrompt.trim().isEmpty()) {
      return "[ERROR] userPrompt is null or empty";
    }

    try {
      String jsonRequest = formatRequestBody(configModel, requestAndResponse, userPrompt);
      String jsonResponse = sendHttpRequest(configModel, jsonRequest);
      return parseResponseBody(jsonResponse);
    } catch (Exception e) {
      return "[ERROR] API request failed: " + e.getMessage();
    }
  }

  /**
   * Format the request body for the specific LLM provider.
   *
   * @param configModel Configuration containing API settings
   * @param requestAndResponse HTTP request and response data
   * @param userPrompt User's analysis prompt
   * @return JSON request body string
   */
  protected abstract String formatRequestBody(
      ConfigModel configModel, HttpHistoryItem requestAndResponse, String userPrompt);

  /**
   * Parse the response body from the specific LLM provider.
   *
   * @param jsonResponse JSON response from the API
   * @return Extracted content from the response
   */
  protected abstract String parseResponseBody(String jsonResponse);

  protected String getAuthorizationHeader(String apiKey) {
    return "Bearer " + apiKey;
  }

  /**
   * Send HTTP request to LLM API using Montoya API
   *
   * <p>This method is public to mock in unit tests
   *
   * @param config Configuration containing endpoint and API key
   * @param jsonRequest JSON request body
   * @return JSON response string
   */
  public String sendHttpRequest(ConfigModel config, String jsonRequest) {
    try {
      HttpRequest httpRequest =
          HttpRequest.httpRequestFromUrl(config.getEndpoint())
              .withMethod("POST")
              .withHeader("Content-Type", "application/json")
              .withHeader("Authorization", getAuthorizationHeader(config.getApiKey()))
              .withBody(jsonRequest);

      HttpRequestResponse requestResponse = montoyaApi.http().sendRequest(httpRequest);

      HttpResponse httpResponse = requestResponse.response();

      if (httpResponse == null) {
        throw new RuntimeException("No response received from API");
      }

      int statusCode = httpResponse.statusCode();
      String responseBody = httpResponse.bodyToString();

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
   * Format HTTP data for analysis
   *
   * @param request HTTP request/response data
   * @return Formatted string for analysis
   */
  protected String formatHttpData(HttpHistoryItem request) {
    StringBuilder data = new StringBuilder();

    data.append(
        "Please analyze this HTTP request and response for security vulnerabilities and potential issues:\\n\\n");

    data.append("=== HTTP REQUEST ===\\n");
    data.append(request.getMethod()).append(" ").append(request.getUrl()).append("\\n");

    if (!request.getHeaders().isEmpty()) {
      data.append("\\nHeaders:\\n");
      for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
        data.append(header.getKey()).append(": ").append(header.getValue()).append("\\n");
      }
    }

    if (!request.getBody().isEmpty()) {
      data.append("\\nRequest Body:\\n");
      data.append(request.getBody()).append("\\n");
    }

    data.append("\\n=== HTTP RESPONSE ===\\n");
    data.append("Status Code: ").append(request.getStatusCode()).append("\\n");

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
   * Escape special characters for JSON strings
   *
   * @param text Text to escape
   * @return Escaped text
   */
  protected String escapeJson(String text) {
    if (text == null) return "";
    return text.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\b", "\\b")
        .replace("\f", "\\f");
  }
}
