package com.airis.burp.ai.llm;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.airis.burp.ai.config.ConfigModel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class OpenAIClientTest {
  private OpenAIClient openAIClient;
  private ConfigModel config;

  @Mock private MontoyaApi mockMontoyaApi;
  @Mock private Http mockHttp;
  @Mock private HttpRequestResponse mockRequestResponse;
  @Mock private HttpResponse mockHttpResponse;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    when(mockMontoyaApi.http()).thenReturn(mockHttp);
    openAIClient = new OpenAIClient(mockMontoyaApi);
    config = new ConfigModel();
  }

  @AfterEach
  public void tearDown() {
    openAIClient = null;
    config = null;
  }

  @Test
  public void testInitialization() {
    config.setProvider("openai");
    config.setEndpoint("https://api.openai.com/v1/chat/completions");
    config.setApiKey("test-key");
  }
}
