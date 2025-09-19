package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class AnalysisEngineSystemTest {

  @Mock private MontoyaApi montoyaApi;
  @Mock private Logging logging;

  private AnalysisEngine sut;
  private ConfigModel configModel;

  private static final String SAMPLE_REQUEST =
      "GET / HTTP/1.1\r\n"
          + "Host: example.com\r\n"
          + "Accept-Language: en-US,en;q=0.9\r\n"
          + "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
          + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9\r\n"
          + "Connection: keep-alive\r\n"
          + "\r\n";

  private static final String SAMPLE_RESPONSE =
      "HTTP/1.1 200 OK\r\n"
          + "Content-Type: text/html; charset=UTF-8\r\n"
          + "Content-Length: 1234\r\n"
          + "Date: Thu, 19 Sep 2025 10:00:00 GMT\r\n"
          + "Server: nginx/1.18.0\r\n"
          + "\r\n"
          + "<html><head><title>Example</title></head><body><h1>Hello World</h1></body></html>";

  @BeforeEach
  void setUp() {
    configModel = new ConfigModel();
    sut = new AnalysisEngine(configModel, logging, montoyaApi);
  }

  @AfterEach
  void tearDown() {
    configModel = null;
    sut = null;
  }

  @Test
  void UnknownProviderShouldReturnsErrorMessage() {
    configModel.setProvider("unknown_provider");
    configModel.setApiKey("test-api-key");
    configModel.setEndpoint("https://test.example.com/api");

    String result = sut.analyze(SAMPLE_REQUEST, SAMPLE_RESPONSE);

    assertEquals("Configuration is incomplete. Please configure API settings.", result);
  }
}
