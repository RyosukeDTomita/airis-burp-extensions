package com.airis.burp.ai;

import static java.util.concurrent.Executors.newFixedThreadPool;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.core.RequestProcessor;
import com.airis.burp.ai.llm.OpenAIClient;
import com.airis.burp.ai.ui.AIAnalysisMenuProvider;
import com.airis.burp.ai.ui.ConfigurationTab;
import java.util.concurrent.ExecutorService;

/**
 * Main Burp extension class. Implements BurpExtension interface to register with Burp Suite.
 * Handles initialization of components and registration of menu items.
 */
public class Extension implements BurpExtension {
  private static final String EXTENSION_NAME = "AIris: request insight system";
  // Tab display name in Burp
  private static final String TAB_NAME = "AIris Config";
  private MontoyaApi api;
  private ConfigModel configModel;
  private RequestProcessor requestProcessor;
  private AnalysisEngine analysisEngine;

  @Override
  public void initialize(MontoyaApi api) {
    this.api = api;

    // Set extension name
    api.extension().setName(EXTENSION_NAME);

    ExecutorService executorService = newFixedThreadPool(3);

    // Initialize components
    initializeComponents();

    // Register UI components
    registerUI();

    // NOTE: Java's garbage collector cleans up objects once there are no references.
    // However, threads, sockets, or file handles are not managed by GC.
    // They must be explicitly shut down using
    // https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/concurrent/ExecutorService.html#shutdownNow().
    api.extension()
        .registerUnloadingHandler(
            () -> {
              api.logging().logToOutput("Extension unloading...");

              // Shutdown executor service
              executorService.shutdownNow();

              // Close all active HTTP connections
              OpenAIClient.closeAllConnections();

              api.logging().logToOutput("Extension unloaded successfully");
            });

    api.logging().logToOutput("Extension loaded successfully");
  }

  /** Initialize core components */
  private void initializeComponents() {
    Logging logging = api.logging();

    try {
      this.configModel = new ConfigModel();
      this.requestProcessor = new RequestProcessor();
      this.analysisEngine = new AnalysisEngine(requestProcessor, configModel, logging);

      logging.logToOutput("Components initialized successfully");
    } catch (Exception e) {
      logging.logToError("Failed to initialize components: " + e.getMessage());
      throw new RuntimeException("Failed to initialize extension", e);
    }
  }

  /** Register UI components including context menu and tabs */
  private void registerUI() {
    Logging logging = api.logging();

    try {
      // Register context menu
      AIAnalysisMenuProvider menuProvider =
          new AIAnalysisMenuProvider(analysisEngine, configModel, api);
      api.userInterface().registerContextMenuItemsProvider(menuProvider);

      // Register configuration tab
      ConfigurationTab configTab = new ConfigurationTab(configModel, logging);
      api.userInterface().registerSuiteTab(TAB_NAME, configTab.getMainPanel());

      logging.logToOutput("UI components registered successfully");
    } catch (Exception e) {
      logging.logToError("Failed to register UI components: " + e.getMessage());
    }
  }
}
