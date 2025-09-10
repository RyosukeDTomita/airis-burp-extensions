package com.airis.burp.ai;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.core.RequestProcessor;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.OpenAIClient;
import com.airis.burp.ai.ui.AIAnalysisMenuProvider;
import com.airis.burp.ai.ui.ConfigurationTab;

/**
 * Main Burp extension class. Implements BurpExtension interface to register with Burp Suite.
 * Handles initialization of components and registration of menu items.
 */
public class Extension implements BurpExtension {
  private static final String EXTENSION_NAME = "AIris: request insight system";
  // Tab display name in Burp
  private static final String TAB_NAME = "AIris Config";
  // Coreコンポーネント 本当はDIしたいけど、BurpExtension形式だと難しいので、ここで生成
  private MontoyaApi api;
  private ConfigModel configModel;
  private LLMClient llmClient;
  private RequestProcessor requestProcessor;
  private AnalysisEngine analysisEngine;

  @Override
  public void initialize(MontoyaApi api) {
    this.api = api;

    // Set extension name
    api.extension().setName(EXTENSION_NAME);

    // Initialize components
    initializeComponents();

    // Register UI components
    registerUI();

    api.logging().logToOutput("Extension loaded successfully");
  }

  /** Initialize core components */
  private void initializeComponents() {
    Logging logging = api.logging();

    try {
      this.configModel = ConfigModel.getInstance();
      this.llmClient = new OpenAIClient();
      this.requestProcessor = new RequestProcessor(llmClient);
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

  // TODO: テストのためだけのpublicなので消す
  public ConfigModel getConfigModel() {
    return configModel;
  }

  // TODO: テストのためだけのpublicなので消す
  public AnalysisEngine getAnalysisEngine() {
    return analysisEngine;
  }

  // TODO: テストのためだけのpublicなので消す
  public LLMClient getLLMClient() {
    return llmClient;
  }

  // TODO: テストのためだけのpublicなので消す
  public RequestProcessor getRequestProcessor() {
    return requestProcessor;
  }
}
