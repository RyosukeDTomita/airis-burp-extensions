package com.airis.burp.ai.core;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents an HTTP request-response pair for security analysis. Contains all relevant information
 * including request method, URL, headers, body, response status code, and response content.
 * Provides parsing functionality for HTTP requests and responses.
 */
public class HttpHistoryItem {
  private String method = "";
  private String url = "";
  private Map<String, String> headers = new HashMap<>();
  private String body = "";
  private int statusCode = 0;
  private String responseBody = "";
  private Map<String, String> responseHeaders = new HashMap<>();

  /**
   * Private constructor for internal use by factory methods.
   */
  private HttpHistoryItem() {
    // Initialize with default values (already set by field declarations)
  }


  /**
   * Creates an HttpHistoryItem from both HTTP request and response strings.
   *
   * @param httpRequest The raw HTTP request string
   * @param httpResponse The raw HTTP response string
   * @return A new HttpHistoryItem with parsed request and response data
   */
  public static HttpHistoryItem fromHttpRequestResponse(String httpRequest, String httpResponse) {
    HttpHistoryItem item = new HttpHistoryItem();
    
    // Parse request
    if (httpRequest != null && !httpRequest.trim().isEmpty()) {
      String[] requestParts = httpRequest.split("\\r\\n\\r\\n", 2);
      String requestHeaderSection = requestParts[0];
      String requestBody = requestParts.length > 1 ? requestParts[1] : "";
      
      String[] requestLines = requestHeaderSection.split("\\r\\n");
      if (requestLines.length > 0) {
        // Parse request line (GET /path HTTP/1.1)
        String requestLine = requestLines[0];
        String[] requestLineParts = requestLine.split(" ");
        if (requestLineParts.length >= 2) {
          item.setMethod(requestLineParts[0]);
          item.setUrl(requestLineParts[1]);
        }
        
        // Parse request headers
        if (requestLines.length > 1) {
          StringBuilder headerLines = new StringBuilder();
          for (int i = 1; i < requestLines.length; i++) {
            headerLines.append(requestLines[i]);
            if (i < requestLines.length - 1) {
              headerLines.append("\r\n");
            }
          }
          Map<String, String> headers = extractHeaders(headerLines.toString());
          item.setHeaders(headers);
        }
      }
      
      item.setBody(requestBody);
    }
    
    // Parse response
    if (httpResponse != null && !httpResponse.trim().isEmpty()) {
      String[] responseParts = httpResponse.split("\\r\\n\\r\\n", 2);
      String responseHeaderSection = responseParts[0];
      String responseBody = responseParts.length > 1 ? responseParts[1] : "";
      
      String[] responseLines = responseHeaderSection.split("\\r\\n");
      if (responseLines.length > 0) {
        // Parse status line (HTTP/1.1 200 OK)
        String statusLine = responseLines[0];
        String[] statusParts = statusLine.split(" ");
        if (statusParts.length >= 2) {
          try {
            int statusCode = Integer.parseInt(statusParts[1]);
            item.setStatusCode(statusCode);
          } catch (NumberFormatException e) {
            item.setStatusCode(0);
          }
        }
        
        // Parse response headers
        if (responseLines.length > 1) {
          StringBuilder headerLines = new StringBuilder();
          for (int i = 1; i < responseLines.length; i++) {
            headerLines.append(responseLines[i]);
            if (i < responseLines.length - 1) {
              headerLines.append("\r\n");
            }
          }
          Map<String, String> responseHeaders = extractHeaders(headerLines.toString());
          item.setResponseHeaders(responseHeaders);
        }
      }
      
      item.setResponseBody(responseBody);
    }
    
    return item;
  }

  /**
   * Extracts HTTP headers from a string of header lines and returns them as a Map.
   *
   * @param headerLines String containing HTTP headers separated by CRLF
   * @return Map of header names to values
   */
  private static Map<String, String> extractHeaders(String headerLines) {
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

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method != null ? method : "";
  }

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url != null ? url : "";
  }

  public Map<String, String> getHeaders() {
    return headers;
  }

  public void setHeaders(Map<String, String> headers) {
    this.headers = headers != null ? headers : new HashMap<>();
  }

  public String getBody() {
    return body;
  }

  public void setBody(String body) {
    this.body = body != null ? body : "";
  }

  public int getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(int statusCode) {
    this.statusCode = statusCode;
  }

  public String getResponseBody() {
    return responseBody;
  }

  public void setResponseBody(String responseBody) {
    this.responseBody = responseBody != null ? responseBody : "";
  }

  public Map<String, String> getResponseHeaders() {
    return responseHeaders;
  }

  public void setResponseHeaders(Map<String, String> responseHeaders) {
    this.responseHeaders = responseHeaders != null ? responseHeaders : new HashMap<>();
  }
}
