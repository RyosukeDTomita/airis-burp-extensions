package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

public class HttpHistoryItemTest {

  @Test
  public void testFromHttpRequest_EmptyRequest() {
    HttpHistoryItem item = HttpHistoryItem.fromHttpRequest("");
    assertEquals("", item.getMethod());
    assertEquals("", item.getUrl());
    assertEquals("", item.getBody());
    assertTrue(item.getHeaders().isEmpty());
  }

  @Test
  public void testFromHttpRequest_NullRequest() {
    HttpHistoryItem item = HttpHistoryItem.fromHttpRequest(null);
    assertEquals("", item.getMethod());
    assertEquals("", item.getUrl());
    assertEquals("", item.getBody());
    assertTrue(item.getHeaders().isEmpty());
  }

  @Test
  public void testFromHttpRequest_BasicRequest() {
    String request = "GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\ntest body";
    HttpHistoryItem item = HttpHistoryItem.fromHttpRequest(request);

    assertEquals("GET", item.getMethod());
    assertEquals("/test", item.getUrl());
    assertEquals("test body", item.getBody());

    Map<String, String> headers = item.getHeaders();
    assertEquals("example.com", headers.get("Host"));
    assertEquals("Test", headers.get("User-Agent"));
  }

  @Test
  public void testParseHttpResponse_EmptyResponse() {
    HttpHistoryItem item = new HttpHistoryItem();
    item.parseHttpResponse("");
    assertEquals(0, item.getStatusCode());
    assertEquals("", item.getResponseBody());
  }

  @Test
  public void testParseHttpResponse_NullResponse() {
    HttpHistoryItem item = new HttpHistoryItem();
    item.parseHttpResponse(null);
    assertEquals(0, item.getStatusCode());
    assertEquals("", item.getResponseBody());
  }

  @Test
  public void testParseHttpResponse_BasicResponse() {
    HttpHistoryItem item = new HttpHistoryItem();
    String response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nresponse body";
    item.parseHttpResponse(response);

    assertEquals(200, item.getStatusCode());
    assertEquals("response body", item.getResponseBody());
  }

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
  public void testParseHttpResponse_InvalidStatusCode() {
    HttpHistoryItem item = new HttpHistoryItem();
    String response = "HTTP/1.1 invalid OK\r\n\r\nresponse body";
    item.parseHttpResponse(response);

    assertEquals(0, item.getStatusCode());
    assertEquals("response body", item.getResponseBody());
  }
}
