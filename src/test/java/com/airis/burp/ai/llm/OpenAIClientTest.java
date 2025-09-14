package com.airis.burp.ai.llm;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;

import com.airis.burp.ai.config.ConfigModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OpenAIClientTest {
  private OpenAIClient openAIClient;
  private ConfigModel config;

  @BeforeEach
  public void setUp() {
    openAIClient = new OpenAIClient();
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
