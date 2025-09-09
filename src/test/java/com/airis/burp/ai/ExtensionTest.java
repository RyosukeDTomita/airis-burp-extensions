package com.airis.burp.ai;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class ExtensionTest {
  private com.airis.burp.ai.Extension extension;

  @Mock private MontoyaApi mockApi;

  @Mock private Extension mockExtension;

  @Mock private Logging mockLogging;

  @Mock private UserInterface mockUserInterface;

  @BeforeEach
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    extension = new com.airis.burp.ai.Extension();

    // Setup mock behaviors
    when(mockApi.extension()).thenReturn(mockExtension);
    when(mockApi.logging()).thenReturn(mockLogging);
    when(mockApi.userInterface()).thenReturn(mockUserInterface);
  }

  @Test
  public void testInitialization() {
    // Execute initialization
    extension.initialize(mockApi);

    // Verify extension name was set
    verify(mockExtension).setName("AIris: request insight system");

    // Verify components were initialized
    assertNotNull(extension.getConfigModel());
    assertNotNull(extension.getAnalysisEngine());
    assertNotNull(extension.getLLMClient());
    assertNotNull(extension.getRequestProcessor());

    // Verify logging
    verify(mockLogging).logToOutput("Components initialized successfully");
    verify(mockLogging).logToOutput("UI components registered successfully");
    verify(mockLogging).logToOutput("Extension loaded successfully");
  }
}
