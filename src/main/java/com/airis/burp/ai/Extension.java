package com.airis.burp.ai;

import static java.util.concurrent.Executors.newFixedThreadPool;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.config.SecureConfigStorage;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.ui.AIAnalysisMenuProvider;
import com.airis.burp.ai.ui.AnalysisResultsTab;
import com.airis.burp.ai.ui.ConfigurationTab;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Main Burp extension class. Implements BurpExtension interface to register with Burp Suite.
 * Handles initialization of components and registration of menu items.
 */
public class Extension implements BurpExtension {
  private static final String EXTENSION_NAME = "AIris: request insight system";
  // Tab display name in Burp
  private static final String CONFIG_TAB_NAME = "AIris Config";
  private static final String RESULTS_TAB_NAME = "Airis Analysis";
  private MontoyaApi api;
  private final AtomicReference<ConfigModel> configModelRef = new AtomicReference<>(null);
  private AnalysisEngine analysisEngine;
  private SecureConfigStorage secureConfigStorage;
  private ExecutorService executorService;
  private ConfigurationTab configurationTab;

  @Override
  public void initialize(MontoyaApi api) {
    this.api = api;

    // Set extension name
    api.extension().setName(EXTENSION_NAME);

    // Initialize executor service for background processing
    executorService = newFixedThreadPool(3);

    // Initialize secure storage and load existing configuration if present
    secureConfigStorage = new SecureConfigStorage(api);
    Optional<ConfigModel> existingConfig = secureConfigStorage.load();
    if (existingConfig.isPresent()) {
      configModelRef.set(existingConfig.get());
      api.logging().logToOutput("Loaded configuration from secure storage.");
    }

    // Initialize components
    initializeComponents();

    // Register UI components
    registerUI(existingConfig);

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

              if (configurationTab != null) {
                configurationTab.dispose();
              }

              // Clear the configuration reference
              configModelRef.set(null);

              api.logging().logToOutput("Extension unloaded successfully");
            });

    api.logging().logToOutput("Extension loaded successfully");
  }

  /** Initialize core components */
  private void initializeComponents() {
    Logging logging = api.logging();

    try {
      this.analysisEngine = new AnalysisEngine(configModelRef::get, logging, api);

      logging.logToOutput("Components initialized successfully");
    } catch (Exception e) {
      logging.logToError("Failed to initialize components: " + e.getMessage());
      throw new RuntimeException("Failed to initialize extension", e);
    }
  }

  /** Register UI components including context menu and tabs */
  private void registerUI(Optional<ConfigModel> existingConfig) {
    Logging logging = api.logging();

    try {
      // Register analysis results tab
      AnalysisResultsTab resultsTab = new AnalysisResultsTab(analysisEngine, api, executorService);
      api.userInterface().registerSuiteTab(RESULTS_TAB_NAME, resultsTab.getMainPanel());

      // Register context menu with results tab reference
      AIAnalysisMenuProvider menuProvider = new AIAnalysisMenuProvider(api);
      menuProvider.setAnalysisResultsTab(resultsTab);
      api.userInterface().registerContextMenuItemsProvider(menuProvider);

      // Register configuration tab
      configurationTab =
          new ConfigurationTab(
              logging,
              newConfig -> {
                configModelRef.set(newConfig);
                secureConfigStorage.save(newConfig);
                logging.logToOutput("Configuration updated and stored securely: " + newConfig);
              },
              secureConfigStorage,
              api);
      api.userInterface().registerSuiteTab(CONFIG_TAB_NAME, configurationTab.getMainPanel());

      if (existingConfig.isPresent()) {
        configurationTab.loadConfiguration(existingConfig.get());
      }

      logging.logToOutput("UI components registered successfully");
    } catch (Exception e) {
      logging.logToError("Failed to register UI components: " + e.getMessage());
    }
  }
}
