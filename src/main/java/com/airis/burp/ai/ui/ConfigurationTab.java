package com.airis.burp.ai.ui;

import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;

/**
 * Configuration tab for AI Extension settings in Burp Suite. Provides UI for configuring AI
 * provider, endpoint, API key, and custom prompts.
 */
public class ConfigurationTab {
  private final ConfigModel configModel;
  private final Logging logging;
  private JPanel mainPanel;
  private JComboBox<String> providerCombo;
  private JTextField endpointField;
  private JPasswordField apiKeyField;
  private JTextArea userPromptArea;
  private JButton saveButton;
  private JButton testButton;
  private JLabel statusLabel;

  public ConfigurationTab(ConfigModel configModel, Logging logging) {
    this.configModel = configModel;
    this.logging = logging;

    initializeUI();
    loadConfiguration();
  }

  /**
   * Get the main component for Burp extension tab
   *
   * @return JComponent to be added to Burp's UI
   */
  public Component getComponent() {
    return mainPanel;
  }

  /** Initialize the UI components */
  private void initializeUI() {
    mainPanel = new JPanel(new BorderLayout());

    // Create form panel
    JPanel formPanel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.insets = new Insets(5, 5, 5, 5);

    // Provider selection
    gbc.gridx = 0;
    gbc.gridy = 0;
    formPanel.add(new JLabel("AI Provider:"), gbc);

    gbc.gridx = 1;
    gbc.weightx = 1.0;
    providerCombo = new JComboBox<>(new String[] {"openai", "anthropic", "gemini"});
    providerCombo.addActionListener(e -> updateEndpointForProvider());
    formPanel.add(providerCombo, gbc);

    // Endpoint
    gbc.gridx = 0;
    gbc.gridy = 1;
    gbc.weightx = 0;
    formPanel.add(new JLabel("API Endpoint:"), gbc);

    gbc.gridx = 1;
    gbc.weightx = 1.0;
    endpointField = new JTextField();
    formPanel.add(endpointField, gbc);

    // API Key
    gbc.gridx = 0;
    gbc.gridy = 2;
    gbc.weightx = 0;
    formPanel.add(new JLabel("API Key:"), gbc);

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
    JButton defaultPromptButton = new JButton("Reset to Default Prompt");

    // Add action for default prompt button
    defaultPromptButton.addActionListener(
        e -> userPromptArea.setText(ConfigModel.DEFAULT_USER_PROMPT));

    buttonPanel.add(saveButton);
    buttonPanel.add(testButton);
    buttonPanel.add(defaultPromptButton);

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

  /** Load existing configuration into UI */
  private void loadConfiguration() {
    if (configModel != null) {
      providerCombo.setSelectedItem(configModel.getProvider());
      endpointField.setText(configModel.getEndpoint());
      apiKeyField.setText(configModel.getApiKey());
      userPromptArea.setText(configModel.getUserPrompt());
    }
  }

  private void updateEndpointForProvider() {
    String provider = (String) providerCombo.getSelectedItem();
    if ("openai".equals(provider)) {
      endpointField.setText("https://api.openai.com/v1/chat/completions");
    } else if ("anthropic".equals(provider)) {
      endpointField.setText("https://api.anthropic.com/v1/messages");
    }
  }

  private class SaveAction implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      try {
        // Update config model
        configModel.setProvider((String) providerCombo.getSelectedItem());
        configModel.setEndpoint(endpointField.getText());
        configModel.setApiKey(new String(apiKeyField.getPassword()));
        configModel.setUserPrompt(userPromptArea.getText());

        // Validate
        if (!configModel.isValid()) {
          statusLabel.setText("Error: All fields are required");
          statusLabel.setForeground(Color.RED);
          return;
        }

        statusLabel.setText("Configuration saved successfully");
        statusLabel.setForeground(Color.GREEN);

        if (logging != null) {
          logging.logToOutput("Configuration saved successfully");
        }

      } catch (Exception ex) {
        statusLabel.setText("Error saving configuration: " + ex.getMessage());
        statusLabel.setForeground(Color.RED);

        if (logging != null) {
          logging.logToError("Failed to save configuration: " + ex.getMessage());
        }
      }
    }
  }

  /** Action handler for test connection button */
  private class TestAction implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      statusLabel.setText("Testing connection...");
      statusLabel.setForeground(Color.BLUE);

      // TODO: Implement actual connection test
      // For now, just validate configuration
      if (configModel.isValid()) {
        statusLabel.setText("Configuration is valid");
        statusLabel.setForeground(Color.GREEN);
      } else {
        statusLabel.setText("Configuration is incomplete");
        statusLabel.setForeground(Color.RED);
      }
    }
  }

  public JPanel getMainPanel() {
    return mainPanel;
  }
}
