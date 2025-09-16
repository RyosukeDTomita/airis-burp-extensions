package com.airis.burp.ai.core;

import java.util.HashMap;
import java.util.Map;

/** Processes HTTP requests and responses for analysis. */
public class RequestProcessor {

  public HttpHistoryItem parseHttpRequest(String httpRequest) {
    HttpHistoryItem request = new HttpHistoryItem();

    if (httpRequest == null || httpRequest.trim().isEmpty()) {
      return request;
    }

    String[] parts = httpRequest.split("\\r\\n\\r\\n", 2);
    String headerSection = parts[0];
    String body = parts.length > 1 ? parts[1] : "";

    String[] lines = headerSection.split("\\r\\n");
    if (lines.length > 0) {
      // Parse request line (GET /path HTTP/1.1)
      String requestLine = lines[0];
      String[] requestParts = requestLine.split(" ");
      if (requestParts.length >= 2) {
        request.setMethod(requestParts[0]);
        request.setUrl(requestParts[1]);
      }

      // Parse headers
      if (lines.length > 1) {
        StringBuilder headerLines = new StringBuilder();
        for (int i = 1; i < lines.length; i++) {
          headerLines.append(lines[i]);
          if (i < lines.length - 1) {
            headerLines.append("\r\n");
          }
        }
        Map<String, String> headers = extractHeaders(headerLines.toString());
        request.setHeaders(headers);
      }
    }

    request.setBody(body);
    return request;
  }

  public void parseHttpResponse(HttpHistoryItem request, String httpResponse) {
    if (httpResponse == null || httpResponse.trim().isEmpty()) {
      return;
    }

    String[] parts = httpResponse.split("\\r\\n\\r\\n", 2);
    String headerSection = parts[0];
    String responseBody = parts.length > 1 ? parts[1] : "";

    String[] lines = headerSection.split("\\r\\n");
    if (lines.length > 0) {
      // Parse status line (HTTP/1.1 200 OK)
      String statusLine = lines[0];
      String[] statusParts = statusLine.split(" ");
      if (statusParts.length >= 2) {
        try {
          int statusCode = Integer.parseInt(statusParts[1]);
          request.setStatusCode(statusCode);
        } catch (NumberFormatException e) {
          request.setStatusCode(0);
        }
      }
    }

    request.setResponseBody(responseBody);
  }

  public HttpHistoryItem createAnalysisRequest(String httpRequest, String httpResponse) {
    HttpHistoryItem requestResponse = parseHttpRequest(httpRequest);
    parseHttpResponse(requestResponse, httpResponse);
    return requestResponse;
  }

  /**
   * Extracts HTTP headers from a string of header lines and returns them as a Map.
   *
   * @param headerLines String containing HTTP headers separated by CRLF
   * @return Map of header names to values
   */
  public Map<String, String> extractHeaders(String headerLines) {
    Map<String, String> headers = new HashMap<>();

    // Return empty map for null or empty input
    if (headerLines == null || headerLines.trim().isEmpty()) {
      return headers;
    }

    // Split header lines by CRLF
    for (String line : headerLines.split("\\r\\n")) {
      // Skip empty lines
      if (line.trim().isEmpty()) {
        continue;
      }

      // Find the colon separator
      int colonIndex = line.indexOf(':');

      // Check if colon exists and is not at start/end of line
      if (colonIndex > 0 && colonIndex < line.length() - 1) {
        String name = line.substring(0, colonIndex).trim();
        String value = line.substring(colonIndex + 1).trim();
        headers.put(name, value);
      }
    }

    return headers;
  }
}
