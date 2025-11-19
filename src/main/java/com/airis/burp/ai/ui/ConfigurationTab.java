package com.airis.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.config.SecureConfigStorage;
import com.airis.burp.ai.core.HttpHistoryItem;
import com.airis.burp.ai.llm.AnthropicClient;
import com.airis.burp.ai.llm.LLMClient;
import com.airis.burp.ai.llm.LLMProviderRegistry;
import com.airis.burp.ai.llm.OpenAIClient;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import javax.swing.*;

/**
 * Configuration tab for AI Extension settings in Burp Suite. Provides UI for configuring AI
 * provider, endpoint, API key, and custom prompts.
 */
public class ConfigurationTab {
  private final Consumer<ConfigModel> onSave;
  private final Logging logging;
  private final SecureConfigStorage secureConfigStorage;
  private final MontoyaApi montoyaApi;
  private final ExecutorService executorService;
  private JPanel mainPanel;
  private JComboBox<String> providerCombo;
  private JTextField endpointField;
  private JTextField modelField;
  private JPasswordField apiKeyField;
  private JButton saveButton;
  private JButton testButton;
  private JLabel statusLabel;

  public ConfigurationTab(
      Logging logging,
      Consumer<ConfigModel> onSave,
      SecureConfigStorage secureConfigStorage,
      MontoyaApi montoyaApi) {
    this.logging = logging;
    this.onSave = onSave;
    this.secureConfigStorage = secureConfigStorage;
    this.montoyaApi = montoyaApi;
    this.executorService = Executors.newSingleThreadExecutor();

    initializeUI();
    loadDefaultValues(); // Load default values into UI
  }

  /** Initialize the UI components */
  private void initializeUI() {
    mainPanel = new JPanel(new BorderLayout());

    // Create form panel
    JPanel formPanel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.insets = new Insets(5, 5, 5, 5);

    // Provider
    gbc.gridx = 0;
    gbc.gridy = 0;
    formPanel.add(new JLabel("AI Provider:"), gbc);

    // Provider select combo box
    gbc.gridx = 1;
    gbc.weightx = 1.0;
  providerCombo = new JComboBox<>(new String[] {"openai", "anthropic"});
  providerCombo.addActionListener(e -> updateEndpointForProvider());
    formPanel.add(providerCombo, gbc);

    // Endpoint
    gbc.gridx = 0;
    gbc.gridy = 1;
    gbc.weightx = 0;
    formPanel.add(new JLabel("API Endpoint:"), gbc);

    // Endpoint text field
    gbc.gridx = 1;
    gbc.weightx = 1.0;
    endpointField = new JTextField();
    formPanel.add(endpointField, gbc);

  // Model
  gbc.gridx = 0;
  gbc.gridy = 2;
  gbc.weightx = 0;
  formPanel.add(new JLabel("Model:"), gbc);

  gbc.gridx = 1;
  gbc.weightx = 1.0;
  modelField = new JTextField();
  formPanel.add(modelField, gbc);

    // API Key
    gbc.gridx = 0;
  gbc.gridy = 3;
    gbc.weightx = 0;
    formPanel.add(new JLabel("API Key:"), gbc);

    // API key field(NOTE: JPasswordField is used for better security).
    gbc.gridx = 1;
    gbc.weightx = 1.0;
    apiKeyField = new JPasswordField();
    formPanel.add(apiKeyField, gbc);

    // Add a filler component to push everything to the top
  gbc.gridx = 0;
  gbc.gridy = 4;
    gbc.gridwidth = 2;
    gbc.weighty = 1.0;
    gbc.fill = GridBagConstraints.BOTH;
    formPanel.add(new JLabel(), gbc);

    // Button panel
    JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
    saveButton = new JButton("Save Configuration");
    testButton = new JButton("Test Connection");
    JButton resetButton = new JButton("Reset All to Default");

    // Add action for reset button
    resetButton.addActionListener(
        e -> {
          this.secureConfigStorage.reset();
          this.loadDefaultValues();
          this.statusLabel.setText("Reset to default configuration");
          this.statusLabel.setForeground(Color.BLUE);
          this.logging.logToOutput("Configuration reset to defaults");
        });

    buttonPanel.add(saveButton);
    buttonPanel.add(testButton);
    buttonPanel.add(resetButton);

    // Status panel
    JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
    statusLabel = new JLabel("Ready");
    statusLabel.setForeground(Color.BLUE);
    statusPanel.add(new JLabel("Status:"));
    statusPanel.add(statusLabel);

    // Wrap form panel to align it to the top-left
    JPanel formWrapper = new JPanel(new BorderLayout());
    formWrapper.add(formPanel, BorderLayout.NORTH);

    // Add components to main panel
    mainPanel.add(formWrapper, BorderLayout.CENTER);

    JPanel bottomPanel = new JPanel(new BorderLayout());
    bottomPanel.add(buttonPanel, BorderLayout.NORTH);
    bottomPanel.add(statusPanel, BorderLayout.SOUTH);
    mainPanel.add(bottomPanel, BorderLayout.SOUTH);

    // Add action listeners
    saveButton.addActionListener(new SaveAction());
    testButton.addActionListener(new TestAction());
  }

  /** Load default values into UI components */
  private void loadDefaultValues() {
    providerCombo.setSelectedItem(LLMProviderRegistry.PROVIDER_OPENAI);
    updateEndpointForProvider();
    apiKeyField.setText("");
  }

  /**
   * Load existing configuration into UI
   *
   * @param model The configuration model to load.
   */
  public void loadConfiguration(ConfigModel configModel) {
    if (configModel == null) {
      return;
    }
    this.providerCombo.setSelectedItem(configModel.getProvider());
    this.endpointField.setText(configModel.getEndpoint());
    this.modelField.setText(configModel.getModel());
    this.apiKeyField.setText(configModel.getApiKey());
  }

  /** Update the endpoint field when the drop down list (provider) is changed */
  private void updateEndpointForProvider() {
    String provider = (String) providerCombo.getSelectedItem();
    endpointField.setText(LLMProviderRegistry.getDefaultEndpoint(provider));
    modelField.setText(LLMProviderRegistry.getDefaultModel(provider));
  }

  /** Action handler for save button. */
  private class SaveAction implements ActionListener {
    /**
     * when the save button is clicked, validate and save the configuration ConfigModel.
     *
     * @param e The action event.
     */
    @Override
    public void actionPerformed(ActionEvent e) {
      try {
        char[] enteredApiKeyChars = apiKeyField.getPassword();
        String enteredApiKey = new String(enteredApiKeyChars);

        ConfigModel newConfig =
            new ConfigModel(
        (String) providerCombo.getSelectedItem(),
        endpointField.getText(),
        modelField.getText(),
        enteredApiKey);
        // Consumer callback to save the configuration
        onSave.accept(newConfig);

        statusLabel.setText("Configuration saved successfully");
        statusLabel.setForeground(Color.GREEN);
        logging.logToOutput("Configuration saved successfully");
      } catch (IllegalArgumentException ex) {
        statusLabel.setText("Error: " + ex.getMessage());
        statusLabel.setForeground(Color.RED);
        logging.logToError("Failed to save configuration: " + ex.getMessage());
      }
    }
  }

  /** Action handler for test connection button */
  private class TestAction implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      statusLabel.setText("Testing configuration...");
      statusLabel.setForeground(Color.BLUE);
      testButton.setEnabled(false);

      // Get current configuration from UI
      String provider = (String) providerCombo.getSelectedItem();
  String endpoint = endpointField.getText();
  String model = modelField.getText();
      char[] apiKeyChars = apiKeyField.getPassword();
      String apiKey = new String(apiKeyChars);

      // Validate configuration
      if (apiKey.isEmpty()) {
        statusLabel.setText("Error: API Key is required");
        statusLabel.setForeground(Color.RED);
        testButton.setEnabled(true);
        return;
      }

      // Test connection asynchronously
      executorService.submit(
          () -> {
            try {
              ConfigModel testConfig = new ConfigModel(provider, endpoint, model, apiKey);

              // Create LLM client based on provider
              LLMClient llmClient;
              switch (provider) {
                case "openai":
                  llmClient = new OpenAIClient(montoyaApi);
                  break;
                case "anthropic":
                  llmClient = new AnthropicClient(montoyaApi);
                  break;
                default:
                  throw new IllegalArgumentException("Unsupported provider: " + provider);
              }

              // Create a simple test request
              HttpHistoryItem testItem =
                  HttpHistoryItem.fromHttpRequestResponse(
                      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                      "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>");

              // Perform test analysis
              String result =
                  llmClient.analyze(
                      testConfig,
                      testItem,
                      "Provide a brief analysis of the following HTTP request and response.");

              // Update UI on success
              SwingUtilities.invokeLater(
                  () -> {
                    if (result != null && !result.isEmpty()) {
                      statusLabel.setText("Connection successful!");
                      statusLabel.setForeground(Color.GREEN);
                      logging.logToOutput("LLM connection test successful");
                    } else {
                      statusLabel.setText("Connection failed: Empty response");
                      statusLabel.setForeground(Color.RED);
                      logging.logToError("LLM connection test failed: Empty response");
                    }
                    testButton.setEnabled(true);
                  });

            } catch (Exception ex) {
              // Update UI on failure
              SwingUtilities.invokeLater(
                  () -> {
                    statusLabel.setText("Connection failed: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                    logging.logToError("LLM connection test failed: " + ex.getMessage());
                    testButton.setEnabled(true);
                  });
            }
          });
    }
  }

  /**
   * Get the main panel for the configuration tab.
   *
   * @return The main panel.
   */
  public JPanel getMainPanel() {
    return mainPanel;
  }

  /** Releases resources associated with this tab. */
  public void dispose() {
    executorService.shutdownNow();
    logging.logToOutput("Configuration tab executor shut down");
  }
}
