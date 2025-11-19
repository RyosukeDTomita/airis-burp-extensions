package com.airis.burp.ai.llm;

import burp.api.montoya.MontoyaApi;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.HttpHistoryItem;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/** OpenAI Client to send requests to the OpenAI API */
public class OpenAIClient extends AbstractLLMClient {
  private static final String DEFAULT_MODEL = "gpt-4o-mini";
  private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

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
    JsonObject requestPayload = new JsonObject();
    String model = configModel.getModel();
    if (model == null || model.trim().isEmpty()) {
      model = DEFAULT_MODEL;
    }
    requestPayload.addProperty("model", model);

    JsonArray messages = new JsonArray();

    JsonObject systemMessage = new JsonObject();
    systemMessage.addProperty("role", "system");
    systemMessage.addProperty("content", DEFAULT_SYSTEM_PROMPT);
    messages.add(systemMessage);

    JsonObject userMessage = new JsonObject();
    userMessage.addProperty("role", "user");
    String content = userPrompt + "\n\n" + this.formatHttpData(requestAndResponse);
    userMessage.addProperty("content", content);
    messages.add(userMessage);

    requestPayload.add("messages", messages);
    requestPayload.addProperty("max_tokens", 1000);
    requestPayload.addProperty("temperature", 0.3);

    return GSON.toJson(requestPayload);
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
