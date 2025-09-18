package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

public class HttpHistoryItemTest {

  @Test
  public void testFromHttpRequestResponse_Complete() {
    String request = "POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\nrequest data";
    String response = "HTTP/1.1 201 Created\r\nLocation: /api/123\r\n\r\ncreated";

    HttpHistoryItem item = HttpHistoryItem.fromHttpRequestResponse(request, response);

    assertEquals("POST", item.getMethod());
    assertEquals("/api", item.getUrl());
    assertEquals("request data", item.getBody());
    assertEquals(201, item.getStatusCode());
    assertEquals("created", item.getResponseBody());
    assertEquals("api.example.com", item.getHeaders().get("Host"));
  }

  @Test
  public void testFromHttpRequestResponse_InvalidStatusCode() {
    String request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    String response = "HTTP/1.1 invalid OK\r\n\r\nresponse body";
    HttpHistoryItem item = HttpHistoryItem.fromHttpRequestResponse(request, response);

    assertEquals(0, item.getStatusCode());
    assertEquals("response body", item.getResponseBody());
  }
}
