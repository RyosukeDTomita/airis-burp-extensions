package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class HttpHistoryItemTest {

  @Test
  public void ParseRequestAndResponseComplete() {
    // Real request from Burp log
    String request =
        "GET / HTTP/1.1\r\n"
            + "Host: example.com\r\n"
            + "Accept-Language: en-US,en;q=0.9\r\n"
            + "Upgrade-Insecure-Requests: 1\r\n"
            + "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n"
            + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
            + "Sec-Ch-Ua: \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"140\"\r\n"
            + "Sec-Ch-Ua-Mobile: ?0\r\n"
            + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
            + "Sec-Fetch-Site: none\r\n"
            + "Sec-Fetch-Mode: navigate\r\n"
            + "Sec-Fetch-User: ?1\r\n"
            + "Sec-Fetch-Dest: document\r\n"
            + "Accept-Encoding: gzip, deflate, br\r\n"
            + "Priority: u=0, i\r\n"
            + "Connection: keep-alive\r\n"
            + "\r\n";

    // Real response from Burp log (HTTP/2 200)
    String response =
        "HTTP/2 200 OK\r\n"
            + "Accept-Ranges: bytes\r\n"
            + "Content-Type: text/html\r\n"
            + "Etag: \"84238dfc8092e5d9c0dac8ef93371a07:1736799080.121134\"\r\n"
            + "Last-Modified: Mon, 13 Jan 2025 20:11:20 GMT\r\n"
            + "Vary: Accept-Encoding\r\n"
            + "Cache-Control: max-age=86000\r\n"
            + "Date: Thu, 18 Sep 2025 05:34:42 GMT\r\n"
            + "Content-Length: 1256\r\n"
            + "Alt-Svc: h3=\":443\"; ma=93600\r\n"
            + "\r\n"
            + "<!doctype html>\n"
            + "<html>\n"
            + "<head>\n"
            + "    <title>Example Domain</title>\n"
            + "\n"
            + "    <meta charset=\"utf-8\" />\n"
            + "    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\n"
            + "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
            + "    <style type=\"text/css\">\n"
            + "    body {\n"
            + "        background-color: #f0f0f2;\n"
            + "        margin: 0;\n"
            + "        padding: 0;\n"
            + "        font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\", \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n"
            + "        \n"
            + "    }\n"
            + "    div {\n"
            + "        width: 600px;\n"
            + "        margin: 5em auto;\n"
            + "        padding: 2em;\n"
            + "        background-color: #fdfdff;\n"
            + "        border-radius: 0.5em;\n"
            + "        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);\n"
            + "    }\n"
            + "    a:link, a:visited {\n"
            + "        color: #38488f;\n"
            + "        text-decoration: none;\n"
            + "    }\n"
            + "    @media (max-width: 700px) {\n"
            + "        div {\n"
            + "            margin: 0 auto;\n"
            + "            width: auto;\n"
            + "        }\n"
            + "    }\n"
            + "    </style>    \n"
            + "</head>\n"
            + "\n"
            + "<body>\n"
            + "<div>\n"
            + "    <h1>Example Domain</h1>\n"
            + "    <p>This domain is for use in illustrative examples in documents. You may use this\n"
            + "    domain in literature without prior coordination or asking for permission.</p>\n"
            + "    <p><a href=\"https://www.iana.org/domains/example\">More information...</a></p>\n"
            + "</div>\n"
            + "</body>\n"
            + "</html>";

    HttpHistoryItem sut = HttpHistoryItem.fromHttpRequestResponse(request, response);

    // check parsed value is correct
    assertEquals("GET", sut.getMethod());
    assertEquals("/", sut.getUrl());
    assertEquals("", sut.getBody()); // GET request has no body

    assertEquals(200, sut.getStatusCode());
    assertTrue(sut.getResponseBody().contains("Example Domain"));
    assertTrue(sut.getResponseBody().contains("<!doctype html>"));

    assertEquals("example.com", sut.getHeaders().get("Host"));
    assertEquals("en-US,en;q=0.9", sut.getHeaders().get("Accept-Language"));
    assertEquals(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        sut.getHeaders().get("User-Agent"));

    // Verify response headers
    assertNotNull(sut.getResponseHeaders());
    assertEquals("text/html", sut.getResponseHeaders().get("Content-Type"));
    assertEquals("bytes", sut.getResponseHeaders().get("Accept-Ranges"));
    assertEquals("1256", sut.getResponseHeaders().get("Content-Length"));
    assertEquals("max-age=86000", sut.getResponseHeaders().get("Cache-Control"));
    assertTrue(sut.getResponseHeaders().containsKey("Etag"));
    assertTrue(sut.getResponseHeaders().containsKey("Last-Modified"));
  }
}
