package com.airis.burp.ai.llm;

import static org.junit.jupiter.api.Assertions.*;

import com.airis.burp.ai.config.ConfigModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OpenAIClientTest {
  private OpenAIClient openAIClient;

  @BeforeEach
  public void setUp() {
    openAIClient = new OpenAIClient();
  }

  @Test
  public void testInitialization() {
    ConfigModel config = ConfigModel.getInstance();
    config.setProvider("openai");
    config.setEndpoint("https://api.openai.com/v1/chat/completions");
    config.setApiKey("test-key");
  }
}
