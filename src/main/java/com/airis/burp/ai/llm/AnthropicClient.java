package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;

/** Anthropic Claude Client to send requests to the Anthropic API */
public class AnthropicClient extends AbstractLLMClient {
  private static final String DEFAULT_MODEL = "claude-3-5-haiku-20241022";
  private static final String SYSTEM_PROMPT =
      "You are an expert security analyst specializing in web application security."
          + "Following the user's prompt, analyze the provided HTTP request and response.\n";
  private static final String API_VERSION = "2023-06-01";

  /**
   * Constructor
   *
   * @param montoyaApi Burp's Montoya API instance
   */
  public AnthropicClient(MontoyaApi montoyaApi) {
    super(montoyaApi);
  }

  @Override
  protected String getDefaultModel() {
    return DEFAULT_MODEL;
  }

  @Override
  protected String getSystemPrompt() {
    return SYSTEM_PROMPT;
  }

  @Override
  protected String getAuthorizationHeader(String apiKey) {
    // Anthropic uses x-api-key header instead of Authorization Bearer
    return apiKey;
  }

  @Override
  protected String sendHttpRequest(ConfigModel config, String jsonRequest) {
    try {
      HttpRequest httpRequest =
          HttpRequest.httpRequestFromUrl(config.getEndpoint())
              .withMethod("POST")
              .withHeader("Content-Type", "application/json")
              .withHeader("x-api-key", config.getApiKey())
              .withHeader("anthropic-version", API_VERSION)
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

  @Override
  protected String formatRequestBody(
      ConfigModel configModel, HttpHistoryItem requestAndResponse, String userPrompt) {

    StringBuilder json = new StringBuilder();
    json.append("{\n");
    json.append("  \"model\": \"").append(getDefaultModel()).append("\",\n");
    json.append("  \"max_tokens\": 1024,\n");
    json.append("  \"temperature\": 0.3,\n");

    // System message
    json.append("  \"system\": \"").append(escapeJson(getSystemPrompt())).append("\",\n");

    // Messages array
    json.append("  \"messages\": [\n");
    json.append("    {\n");
    json.append("      \"role\": \"user\",\n");

    StringBuilder userContent = new StringBuilder();
    if (userPrompt != null && !userPrompt.isEmpty()) {
      userContent.append(userPrompt).append("\n\n");
    }
    userContent.append(formatHttpData(requestAndResponse));

    json.append("      \"content\": \"").append(escapeJson(userContent.toString())).append("\"\n");
    json.append("    }\n");
    json.append("  ]\n");
    json.append("}");

    return json.toString();
  }

  @Override
  protected String parseResponseBody(String jsonResponse) {
    try {
      // Anthropic returns content in a different structure
      // Look for content array with text blocks
      String searchKey = "\"text\":";
      int startIndex = jsonResponse.indexOf(searchKey);
      if (startIndex == -1) {
        // Fallback to looking for content field
        searchKey = "\"content\":";
        startIndex = jsonResponse.indexOf(searchKey);
        if (startIndex == -1) {
          return "No content found in response";
        }
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
