package com.airis.burp.ai.ui;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.config.SecureConfigStorage;
import com.airis.burp.ai.llm.LLMProviderRegistry;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
  private JPanel mainPanel;
  private JComboBox<String> providerCombo;
  private JTextField endpointField;
  private JPasswordField apiKeyField;
  private JTextArea userPromptArea;
  private JButton saveButton;
  private JButton testButton;
  private JLabel statusLabel;

  public ConfigurationTab(
      Logging logging, Consumer<ConfigModel> onSave, SecureConfigStorage secureConfigStorage) {
    this.logging = logging;
    this.onSave = onSave;
    this.secureConfigStorage = secureConfigStorage;

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

    // API Key
    gbc.gridx = 0;
    gbc.gridy = 2;
    gbc.weightx = 0;
    formPanel.add(new JLabel("API Key:"), gbc);

    // API key field(NOTE: JPasswordField is used for better security).
    gbc.gridx = 1;
    gbc.weightx = 1.0;
    apiKeyField = new JPasswordField();
    formPanel.add(apiKeyField, gbc);

    // User Prompt
    gbc.gridx = 0;
    gbc.gridy = 3;
    gbc.weightx = 0;
    gbc.anchor = GridBagConstraints.NORTH;
    formPanel.add(new JLabel("Analysis Prompt:"), gbc);

    // User prompt text area
    gbc.gridx = 1;
    gbc.weightx = 1.0;
    gbc.weighty = 1.0;
    gbc.fill = GridBagConstraints.BOTH;
    userPromptArea = new JTextArea(10, 50);
    userPromptArea.setLineWrap(true);
    userPromptArea.setWrapStyleWord(true);
    JScrollPane scrollPane = new JScrollPane(userPromptArea);
    formPanel.add(scrollPane, gbc);

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

    // Add components to main panel
    mainPanel.add(formPanel, BorderLayout.CENTER);

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
    providerCombo.setSelectedItem("openai");
    endpointField.setText("https://api.openai.com/v1/chat/completions");
    apiKeyField.setText("");
    userPromptArea.setText(ConfigModel.DEFAULT_USER_PROMPT);
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
    this.apiKeyField.setText(configModel.getApiKey());
    this.userPromptArea.setText(configModel.getUserPrompt());
  }

  /** Update the endpoint field when the drop down list (provider) is changed */
  private void updateEndpointForProvider() {
    String provider = (String) providerCombo.getSelectedItem();
    endpointField.setText(LLMProviderRegistry.getDefaultEndpoint(provider));
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
                enteredApiKey,
                userPromptArea.getText());
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
      // TODO: そのうちテスト処理を実装する
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
}
