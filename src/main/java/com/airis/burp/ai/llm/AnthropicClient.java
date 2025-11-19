package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/** Anthropic Claude Client to send requests to the Anthropic API */
public class AnthropicClient extends AbstractLLMClient {
  private static final String DEFAULT_MODEL = "claude-3-5-haiku-20241022";
  private static final String API_VERSION = "2023-06-01";
  private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

  /**
   * Constructor
   *
   * @param montoyaApi Burp's Montoya API instance
   */
  public AnthropicClient(MontoyaApi montoyaApi) {
    super(montoyaApi);
  }

  @Override
  protected String getAuthorizationHeader(String apiKey) {
    // Anthropic uses x-api-key header instead of Authorization Bearer
    // Return empty string as we'll override buildHttpRequest
    return "";
  }

  @Override
  protected HttpRequest buildHttpRequest(ConfigModel config, String jsonRequest) {
    HttpRequest baseRequest = super.buildHttpRequest(config, jsonRequest);
    return baseRequest
        .withRemovedHeader("Authorization")
        .withHeader("x-api-key", config.getApiKey())
        .withHeader("anthropic-version", API_VERSION);
  }

  @Override
  protected String formatRequestBody(
      ConfigModel configModel, HttpHistoryItem requestAndResponse, String userPrompt) {

    JsonObject payload = new JsonObject();
    payload.addProperty("model", DEFAULT_MODEL);
    payload.addProperty("system", DEFAULT_SYSTEM_PROMPT);
    payload.addProperty("max_tokens", 1024);
    payload.addProperty("temperature", 0.3);

    JsonArray messages = new JsonArray();
    JsonObject userMessage = new JsonObject();
    userMessage.addProperty("role", "user");

    JsonArray contentBlocks = new JsonArray();
    JsonObject textBlock = new JsonObject();
    textBlock.addProperty("type", "text");
    textBlock.addProperty("text", userPrompt + "\n\n" + formatHttpData(requestAndResponse));
    contentBlocks.add(textBlock);

    userMessage.add("content", contentBlocks);
    messages.add(userMessage);
    payload.add("messages", messages);

    String jsonString = GSON.toJson(payload);
    montoyaApi.logging().logToOutput("[DEBUG] JSON length: " + jsonString.length() + " bytes");
    montoyaApi.logging().logToOutput("[DEBUG] JSON is valid: " + jsonString.endsWith("}"));
    montoyaApi.logging().logToOutput("[DEBUG] Request JSON: " + jsonString);
    return jsonString;
  }

  @Override
  protected String parseResponseBody(String jsonResponse) {
    // montoyaApi.logging().logToOutput("[DEBUG] Response JSON: " + jsonResponse);
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
