package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Abstract base class for LLM client implementations. */
public abstract class AbstractLLMClient implements LLMClient {
  protected final MontoyaApi montoyaApi;
  public static final String DEFAULT_SYSTEM_PROMPT =
      "You are an AI assistant specialized in cybersecurity. Answer the user's questions related to HTTP requests and responses.";

  /**
   * Constructor
   *
   * @param montoyaApi Burp's Montoya API instance
   */
  protected AbstractLLMClient(MontoyaApi montoyaApi) {
    this.montoyaApi = montoyaApi;
  }

  /**
   * Analyze an HTTP request/response pair using the AI model with custom prompt.
   *
   * @param configModel Configuration model containing API settings
   * @param requestAndResponse HTTP request and response data
   * @param customPrompt Custom user prompt for analysis
   * @return Analysis response from the AI model
   */
  @Override
  public String analyze(
      ConfigModel configModel, HttpHistoryItem requestAndResponse, String customPrompt) {
    if (requestAndResponse == null) {
      return "[ERROR] requestAndResponse is null";
    }

    montoyaApi
        .logging()
        .logToOutput(
            "Using custom prompt in LLM client: "
                + customPrompt.substring(0, Math.min(50, customPrompt.length()))
                + "...");

    try {
      String jsonRequest = formatRequestBody(configModel, requestAndResponse, customPrompt);
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
   * Build HTTP request with custom headers. Override this method to customize the request.
   *
   * @param config Configuration containing API settings
   * @param jsonRequest JSON request body
   * @return HttpRequest with all headers configured
   */
  protected HttpRequest buildHttpRequest(ConfigModel config, String jsonRequest) {
    try {
      URI endpointUri = new URI(config.getEndpoint());
      String scheme = endpointUri.getScheme() != null ? endpointUri.getScheme() : "https";
      boolean secure = scheme.equalsIgnoreCase("https");
      String host = endpointUri.getHost();
      if (host == null || host.isEmpty()) {
        throw new IllegalArgumentException(
            "Endpoint must include a valid host: " + config.getEndpoint());
      }

      int port = endpointUri.getPort();
      if (port == -1) {
        port = secure ? 443 : 80;
      }

      String path = endpointUri.getRawPath();
      if (path == null || path.isEmpty()) {
        path = "/";
      }
      String query = endpointUri.getRawQuery();
      if (query != null && !query.isEmpty()) {
        path += "?" + query;
      }

    HttpService service = HttpService.httpService(host, port, secure);

    return HttpRequest.httpRequest()
      .withService(service)
      .withMethod("POST")
          .withPath(path)
          .withBody(ByteArray.byteArray(jsonRequest.getBytes(StandardCharsets.UTF_8)))
      .withHeader("Host", host)
      .withHeader("Content-Type", "application/json; charset=UTF-8")
      .withHeader("Accept", "application/json")
      .withHeader("Authorization", getAuthorizationHeader(config.getApiKey()));
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(
          "Invalid LLM endpoint URL: " + config.getEndpoint(), e);
    }
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
      HttpRequest httpRequest = buildHttpRequest(config, jsonRequest);

      HttpRequestResponse requestResponse = montoyaApi.http().sendRequest(httpRequest);

      HttpResponse httpResponse = requestResponse.response();

      if (httpResponse == null) {
        throw new RuntimeException("No response received from API");
      }

  int statusCode = httpResponse.statusCode();
      ByteArray bodyBytes = httpResponse.body();
      if (bodyBytes == null) {
        throw new RuntimeException("API response did not include a body");
      }

      String responseBody = new String(bodyBytes.getBytes(), StandardCharsets.UTF_8);

      if (statusCode >= 400) {
        montoyaApi.logging().logToError("[ERROR] HTTP " + statusCode + " Error: " + responseBody);
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

    data.append("=== HTTP REQUEST ===\n");
    data.append(request.getMethod()).append(" ").append(request.getUrl()).append("\n");
    if (!request.getHeaders().isEmpty()) {
      data.append("\nHeaders:\n");
      for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
        data.append(header.getKey()).append(": ").append(header.getValue()).append("\n");
      }
    }
    if (!request.getBody().isEmpty()) {
      data.append("\nRequest Body:\n");
      data.append(request.getBody()).append("\n");
    }

    data.append("\n=== HTTP RESPONSE ===\n");
    data.append("Status Code: ").append(request.getStatusCode()).append("\n");
    if (!request.getResponseBody().isEmpty()) {
      data.append("\nResponse Body:\n");
      data.append(request.getResponseBody()).append("\n");
    }
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
