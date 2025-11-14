package com.airis.burp.ai.core;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a single analysis result entry in the results table. Contains all information about an
 * analyzed HTTP request.
 */
public class AnalysisResult {
  private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

  private final String url;
  private final LocalDateTime timestamp;
  private String status;
  private String prompt;
  private String result;
  private final HttpHistoryItem httpHistoryItem;

  /** Status constants for analysis progress */
  public static final String STATUS_PENDING = "Pending";

  public static final String STATUS_RUNNING = "Running";
  public static final String STATUS_COMPLETE = "Complete";
  public static final String STATUS_ERROR = "Error";

  /**
   * Creates a new analysis result entry
   *
   * @param url The URL being analyzed
   * @param prompt The prompt to send to AI
   * @param httpHistoryItem The HTTP request/response data
   */
  public AnalysisResult(String url, String prompt, HttpHistoryItem httpHistoryItem) {
    this.url = url;
    this.timestamp = LocalDateTime.now();
    this.status = STATUS_PENDING;
    this.prompt = prompt;
    this.result = "";
    this.httpHistoryItem = httpHistoryItem;
  }

  public String getUrl() {
    return url;
  }

  public String getTimestamp() {
    return timestamp.format(TIME_FORMATTER);
  }

  public LocalDateTime getTimestampObject() {
    return timestamp;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getPrompt() {
    return prompt;
  }

  public void setPrompt(String prompt) {
    this.prompt = prompt;
  }

  public String getResult() {
    return result;
  }

  public void setResult(String result) {
    this.result = result;
  }

  public HttpHistoryItem getHttpHistoryItem() {
    return httpHistoryItem;
  }
}
